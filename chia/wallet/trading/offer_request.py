import dataclasses
import inspect
import math

from blspy import AugSchemeMPL, G1Element, G2Element
from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Tuple, Union

from chia.types.announcement import Announcement
from chia.types.blockchain_format.coin import Coin, coin_as_list
from chia.types.blockchain_format.program import Program
from chia.types.blockchain_format.sized_bytes import bytes32, bytes48
from chia.types.coin_spend import CoinSpend
from chia.types.spend_bundle import SpendBundle
from chia.util.ints import uint16, uint64
from chia.wallet.outer_puzzles import AssetType
from chia.wallet.payment import Payment
from chia.wallet.puzzle_drivers import cast_to_int, PuzzleInfo, Solver
from chia.wallet.puzzles.puzzle_utils import (
    make_assert_coin_announcement,
    make_create_coin_announcement,
    make_create_coin_condition,
    make_create_puzzle_announcement,
    make_reserve_fee_condition,
)
from chia.wallet.standard_wallet_actions import (
    AssertAnnouncement,
    DirectPayment,
    Fee,
    MakeAnnouncement,
    OfferedAmount,
)
from chia.wallet.trading.offer import OFFER_MOD
from chia.wallet.trading.spend_dependencies import (
    DEPENDENCY_WRAPPERS,
    DLDataInclusion,
    SpendDependency,
    RequestedPayment,
)
from chia.wallet.util.wallet_types import WalletType
from chia.wallet.wallet_protocol import WalletProtocol


async def old_request_to_new(
    wallet_state_manager: Any,
    offer_dict: Dict[Optional[bytes32], int],
    driver_dict: Dict[bytes32, PuzzleInfo],
    solver: Solver,
    fee: uint64,
) -> Tuple[Solver, Dict[bytes32, PuzzleInfo]]:
    """
    This method takes an old style offer dictionary and converts it to a new style action specification
    """
    final_solver: Dict[str, Any] = solver.info

    offered_assets: Dict[Optional[bytes32], int] = {k: v for k, v in offer_dict.items() if v < 0}
    requested_assets: Dict[Optional[bytes32], int] = {k: v for k, v in offer_dict.items() if v > 0}

    # When offers first came out, they only supported CATs and driver_dict did not exist
    # We need to fill in any requested assets that do not exist in driver_dict already as CATs
    cat_assets: Dict[bytes32, PuzzleInfo] = {
        key: PuzzleInfo({"type": AssetType.CAT.value, "tail": "0x" + key.hex()})
        for key in requested_assets
        if key is not None and key not in driver_dict
    }
    driver_dict.update(cat_assets)

    # Keep track of the DL assets since they show up under the offered asset's name
    dl_dependencies: List[Solver] = []
    # DLs need to do an announcement after they update so we'll keep track of those to add at the end
    additional_actions: List[Dict[str, Any]] = []

    if "actions" not in final_solver:
        final_solver.setdefault("actions", [])
        for asset_id, amount in offered_assets.items():

            # Get the wallet
            if asset_id is None:
                wallet = wallet_state_manager.main_wallet
            else:
                wallet = await wallet_state_manager.get_wallet_for_asset_id(asset_id.hex())

            # We need to fill in driver dict entries that we can and raise on discrepencies
            if callable(getattr(wallet, "get_puzzle_info", None)):
                puzzle_driver: PuzzleInfo = await wallet.get_puzzle_info(asset_id)
                if asset_id in driver_dict and driver_dict[asset_id] != puzzle_driver:
                    raise ValueError(f"driver_dict specified {driver_dict[asset_id]}, was expecting {puzzle_driver}")
                else:
                    driver_dict[asset_id] = puzzle_driver
            elif asset_id is not None:
                raise ValueError(f"Wallet for asset id {asset_id} is not properly integrated for trading")

            # Build the specification for the asset type we want to offer
            asset_types: List[Dict[str, Any]] = []
            if asset_id is not None:
                puzzle_info: PuzzleInfo = driver_dict[asset_id]
                while True:
                    type_description: Dict[str, Any] = puzzle_info.info
                    if "also" in type_description:
                        del type_description["also"]
                        puzzle_info = puzzle_info.also()
                        asset_types.append(type_description)
                    else:
                        asset_types.append(type_description)
                        break

            # We're passing everything in as a dictionary now instead of a single asset_id/amount pair
            offered_asset: Dict[str, Any] = {"with": {"asset_types": asset_types, "amount": str(abs(amount))}, "do": []}

            if wallet.type() == WalletType.DATA_LAYER:
                try:
                    this_solver: Solver = solver[asset_id.hex()]
                except KeyError:
                    this_solver = solver["0x" + asset_id.hex()]
                # Data Layer offers initially were metadata updates, so we shouldn't allow any kind of sending
                offered_asset["do"] = [
                    [
                        {
                            "type": "update_metadata",
                            # The request used to require "new_root" be in solver so the potential KeyError is good
                            "new_metadata": "0x" + this_solver["new_root"].hex(),
                        }
                    ],
                ]

                additional_actions.append(
                    {
                        "with": offered_asset["with"],
                        "do": [
                            MakeAnnouncement("puzzle", Program.to(b"$")).to_solver(),
                        ],
                    }
                )

                dl_dependencies.extend(
                    [
                        {
                            "type": "dl_data_inclusion",
                            "launcher_id": "0x" + dep["launcher_id"].hex(),
                            "values_to_prove": ["0x" + v.hex() for v in dep["values_to_prove"]],
                        }
                        for dep in this_solver["dependencies"]
                    ]
                )
            else:
                action_batch = [
                    # This is the parallel to just specifying an amount to offer
                    OfferedAmount(abs(amount)).to_solver()
                ]
                # Royalty payments are automatically worked in when you offer fungible assets for an NFT
                if asset_id is None or driver_dict[asset_id].type() != AssetType.SINGLETON.value:
                    for payment in calculate_royalty_payments(requested_assets, abs(amount), driver_dict):
                        action_batch.append(OfferedAmount(payment.amount).to_solver())
                        offered_asset["with"]["amount"] = str(cast_to_int(Solver(offered_asset["with"])["amount"]) + payment.amount)

                # The standard XCH should pay the fee
                if asset_id is None and fee > 0:
                    action_batch.append(Fee(fee).to_solver())
                    offered_asset["with"]["amount"] = str(cast_to_int(Solver(offered_asset["with"])["amount"]) + fee)

                # Provenant NFTs by default clear their ownership on transfer
                elif driver_dict[asset_id].check_type(
                    [
                        AssetType.SINGLETON.value,
                        AssetType.METADATA.value,
                        AssetType.OWNERSHIP.value,
                    ]
                ):
                    action_batch.append(
                        {
                            "type": "update_state",
                            "update": {
                                "new_owner": "()",
                            },
                        }
                    )
                offered_asset["do"] = action_batch

            final_solver["actions"].append(offered_asset)

        final_solver["actions"].extend(additional_actions)

    # Make sure the fee gets into the solver
    if None not in offer_dict and fee > 0:
        final_solver["actions"].append(
            {
                "with": {"amount": fee},
                "do": [
                    Fee(fee).to_solver(),
                ],
            }
        )

    # Now lets use the requested items to fill in the bundle dependencies
    if "dependencies" not in final_solver:
        final_solver.setdefault("dependencies", dl_dependencies)
        for asset_id, amount in requested_assets.items():
            if asset_id is None:
                wallet = wallet_state_manager.main_wallet
            else:
                wallet = await wallet_state_manager.get_wallet_for_asset_id(asset_id.hex())

            p2_ph = await wallet_state_manager.main_wallet.get_new_puzzlehash()

            if wallet.type() != WalletType.DATA_LAYER:  # DL singletons are not sent as part of offers by default
                # Asset/amount pairs are assumed to mean requested_payments
                asset_types: List[Solver] = []
                asset_driver = driver_dict[asset_id]
                while True:
                    if asset_driver.type() == AssetType.CAT.value:
                        asset_types.append(
                            Solver(
                                {
                                    "type": AssetType.CAT.value,
                                    "asset_id": asset_driver["tail"],
                                }
                            )
                        )
                    elif asset_driver.type() == AssetType.SINGLETON.value:
                        asset_types.append(
                            Solver(
                                {
                                    "type": AssetType.SINGLETON.value,
                                    "launcher_id": asset_driver["launcher_id"],
                                    "launcher_ph": asset_driver["launcher_ph"],
                                }
                            )
                        )
                    elif asset_driver.type() == AssetType.METADATA.value:
                        asset_types.append(
                            Solver(
                                {
                                    "type": AssetType.METADATA.value,
                                    "metadata": asset_driver["metadata"],
                                    "metadata_updater_hash": asset_driver["updater_hash"],
                                }
                            )
                        )
                    elif asset_driver.type() == AssetType.OWNERSHIP.value:
                        asset_types.append(
                            Solver(
                                {
                                    "type": AssetType.OWNERSHIP.value,
                                    "owner": asset_driver["owner"],
                                    "transfer_program": asset_driver["transfer_program"],
                                }
                            )
                        )

                    if asset_driver.also() is None:
                        break
                    else:
                        asset_driver = asset_driver.also()

                final_solver["dependencies"].append(
                    {
                        "type": "requested_payment",
                        "asset_types": asset_types,
                        "payment": {
                            "puzhash": "0x" + p2_ph.hex(),
                            "amount": str(amount),
                            "memos": ["0x" + p2_ph.hex()],
                        },
                    }
                )

            # Also request the royalty payment as a formality
            if asset_id is None or driver_dict[asset_id].type() != AssetType.SINGLETON.value:
                final_solver["dependencies"].extend(
                    [
                        {
                            "type": "requested_payment",
                            "asset_id": "0x" + asset_id.hex(),
                            "nonce": "0x" + asset_id.hex(),
                            "payment": {
                                "puzhash": "0x" + payment.address.hex(),
                                "amount": str(payment.amount),
                                "memos": ["0x" + memo.hex() for memo in payment.memos],
                            },
                        }
                        for payment in calculate_royalty_payments(offered_assets, amount, driver_dict)
                    ]
                )

    # Finally, we need to special case any stuff that the solver was previously used for
    if "solving_information" not in final_solver:
        final_solver.setdefault("solving_information", [])

    return Solver(final_solver)


def calculate_royalty_payments(
    requested_assets: Dict[Optional[bytes32], int],
    offered_amount: int,
    driver_dict: Dict[bytes32, PuzzleInfo],
) -> List[Payment]:
    """
    Given assets on one side of a trade and an amount being paid for them, return the payments that must be made
    """
    # First, let's take note of all the royalty enabled NFTs
    royalty_nft_assets: List[bytes32] = [
        asset
        for asset in requested_assets
        if asset is not None
        and driver_dict[asset].check_type(  # check if asset is an Royalty Enabled NFT
            [
                AssetType.SINGLETON.value,
                AssetType.METADATA.value,
                AssetType.OWNERSHIP.value,
            ]
        )
    ]

    # Then build what royalty payments we need to make
    royalty_payments: List[Payment] = []
    for asset_id in royalty_nft_assets:
        transfer_info = driver_dict[asset_id].also().also()  # type: ignore
        assert isinstance(transfer_info, PuzzleInfo)
        address: bytes32 = bytes32(transfer_info["transfer_program"]["royalty_address"])
        pts: uint16 = uint16(transfer_info["transfer_program"]["royalty_percentage"])
        extra_royalty_amount = uint64(math.floor(math.floor(offered_amount / len(royalty_nft_assets)) * (pts / 10000)))
        royalty_payments.append(Payment(address, extra_royalty_amount, [address]))

    return royalty_payments


def parse_dependency(dependency: Solver, nonce: bytes32) -> SpendDependency:
    if dependency["type"] == "requested_payment":
        payment: Solver = dependency["payment"]
        return RequestedPayment(
            nonce,
            dependency["asset_types"],
            Payment(payment["puzhash"], cast_to_int(payment["amount"]), payment["memos"]),
        )
    elif dependency["type"] == "dl_data_inclusion":
        return DLDataInclusion(nonce, dependency["launcher_id"], dependency["values_to_prove"])


def parse_delegated_puzzles(delegated_puzzle: Program, delegated_solution: Program) -> List[SpendDependency]:
    dependencies: List[SpendDependency] = []
    while True:
        mod, curried_args = delegated_puzzle.uncurry()
        try:
            dependency = DEPENDENCY_WRAPPERS[mod]
        except KeyError:
            raise ValueError(f"Saw a delegated puzzle that we are not aware of {mod}")
        dependencies.append(dependency.from_puzzle(mod, curried_args))
    return dependencies


def sort_coin_list(coins: List[Coin]) -> List[Coin]:
    # This sort should be reproducible in CLVM with `>s`
    return sorted(coins, key=Coin.name)


def select_independent_coin(coins: List[Coin]) -> Coin:
    return sort_coin_list(coins)[0]


def nonce_coin_list(coins: List[Coin]) -> bytes32:
    sorted_coin_list: List[List[Union[bytes32, uint64]]] = [coin_as_list(c) for c in coins]
    return Program.to(sorted_coin_list).get_tree_hash()


async def build_spend(wallet_state_manager: Any, solver: Solver, previous_actions: List[CoinSpend]) -> List[CoinSpend]:
    outer_wallets: Dict[Coin, OuterWallet] = {}
    inner_wallets: Dict[Coin, InnerWallet] = {}
    outer_constructors: Dict[Coin, Solver] = {}
    inner_constructors: Dict[Coin, Solver] = {}

    # Keep track of all the new spends in case we want to secure them with announcements
    spend_group: List[CoinSpend] = []

    for action_spec in solver["actions"]:
        # Step 1: Determine which coins, wallets, and puzzle reveals we need to complete the action
        coin_spec: Solver = action_spec["with"]

        coin_infos: Dict[
            Coin, Tuple[OuterWallet, Solver, InnerWallet, Solver]
        ] = await wallet_state_manager.get_coin_infos_for_spec(coin_spec, previous_actions)

        for coin, info in coin_infos.items():
            outer_wallet, outer_constructor, inner_wallet, inner_constructor = info
            outer_wallets[coin] = outer_wallet
            inner_wallets[coin] = inner_wallet
            outer_constructors[coin] = outer_constructor
            inner_constructors[coin] = inner_constructor

        # Step 2: Figure out what coins are responsible for each action
        outer_actions: Dict[Coin, List[WalletAction]] = {}
        inner_actions: Dict[Coin, List[WalletAction]] = {}
        actions_left: List[Solver] = action_spec["do"]
        for coin in coin_infos:
            outer_wallet = outer_wallets[coin]
            inner_wallet = inner_wallets[coin]
            # Get a list of the actions that each wallet supports
            outer_action_parsers = outer_wallet.get_outer_actions()
            inner_action_parsers = inner_wallet.get_inner_actions()

            # Apply any actions that the coin supports
            new_actions_left: List[Solver] = []
            coin_outer_actions: List[WalletAction] = []
            coin_inner_actions: List[WalletAction] = []
            for action in actions_left:
                if action["type"] in outer_action_parsers:
                    coin_outer_actions.append(outer_action_parsers[action["type"]](action))
                elif action["type"] in inner_action_parsers:
                    coin_inner_actions.append(inner_action_parsers[action["type"]](action))
                else:
                    new_actions_left.append(action)

            # Let the outer wallet potentially modify the actions (for example, adding hints to payments)
            new_outer_actions, new_inner_actions = await outer_wallet.check_and_modify_actions(
                coin, coin_outer_actions, coin_inner_actions
            )

            # Double check that the new inner actions are still okay with the inner wallet
            for inner_action in new_inner_actions:
                if inner_action.name() not in inner_action_parsers:
                    continue

            outer_actions[coin] = new_outer_actions
            inner_actions[coin] = new_inner_actions
            actions_left = new_actions_left

        if len(actions_left) > 0:  # Not all actions were handled
            raise ValueError(f"Could not complete actions with specified coins {actions_left}")

        # Step 3: Create all of the coin spends
        new_coin_spends: List[CoinSpend] = []
        for coin in coin_infos:
            outer_wallet = outer_wallets[coin]
            inner_wallet = inner_wallets[coin]

            # Create the inner puzzle and solution first
            inner_puzzle = await inner_wallet.construct_inner_puzzle(inner_constructors[coin])
            inner_solution = await inner_wallet.construct_inner_solution(inner_actions[coin])

            # Then feed those to the outer wallet
            outer_puzzle = await outer_wallet.construct_outer_puzzle(outer_constructors[coin], inner_puzzle)
            outer_solution = await outer_wallet.construct_outer_solution(outer_actions[coin], inner_solution)

            new_coin_spends.append(CoinSpend(coin, outer_puzzle, outer_solution))

        # (Optional) Step 4: Investigate the coin spends and fill in the change data
        if "change" not in solver or solver["change"] != Program.to(None):
            input_amount: int = sum(cs.coin.amount for cs in new_coin_spends)
            output_amount: int = sum(c.amount for cs in new_coin_spends for c in cs.additions())
            fees: int = sum(cs.reserved_fee() for cs in new_coin_spends)
            if output_amount + fees < input_amount:
                change_satisfied: bool = False
                coin_spends_after_change: List[CoinSpend] = []
                for coin_spend in new_coin_spends:
                    if change_satisfied:
                        coin_spends_after_change.append(coin_spend)
                        continue

                    outer_wallet = outer_wallets[coin_spend.coin]
                    inner_wallet = inner_wallets[coin_spend.coin]
                    # Get a list of the actions that each wallet supports
                    outer_action_parsers = outer_wallet.get_outer_actions()
                    inner_action_parsers = inner_wallet.get_inner_actions()

                    change_action = DirectPayment(
                        Payment(await inner_wallet.get_new_puzzlehash(), input_amount - (output_amount + fees), []), []
                    )

                    if change_action.name() in outer_action_parsers:
                        new_outer_actions = [*outer_actions[coin_spend.coin], change_action]
                        new_inner_actions = inner_actions[coin_spend.coin]
                    elif change_action.name() in inner_action_parsers:
                        new_outer_actions = outer_actions[coin_spend.coin]
                        new_inner_actions = [*inner_actions[coin_spend.coin], change_action]

                    # Let the outer wallet potentially modify the actions (for example, adding hints to payments)
                    new_outer_actions, new_inner_actions = await outer_wallet.check_and_modify_actions(
                        coin_spend.coin, new_outer_actions, new_inner_actions
                    )
                    # Double check that the new inner actions are still okay with the inner wallet
                    for inner_action in new_inner_actions:
                        if inner_action.name() not in inner_action_parsers:
                            coin_spends_after_change.append(coin_spend)
                            continue

                    inner_solution = await inner_wallet.construct_inner_solution(new_inner_actions)
                    outer_solution = await outer_wallet.construct_outer_solution(new_outer_actions, inner_solution)

                    coin_spends_after_change.append(dataclasses.replace(coin_spend, solution=outer_solution))

                    change_satisfied = True

                if not change_satisfied:
                    raise ValueError("Could not create change for the specified spend")

                new_coin_spends = coin_spends_after_change

        previous_actions.extend(new_coin_spends)
        spend_group.extend(new_coin_spends)

    # (Optional) Step 5: Secure the coin spends with an announcement ring
    if "security_announcements" not in solver or solver["security_announcements"] != Program.to(None):
        coin_spends_after_announcements: List[CoinSpend] = []
        nonce: bytes32 = nonce_coin_list([cs.coin for cs in spend_group])
        for i, coin_spend in enumerate(spend_group):
            outer_wallet = outer_wallets[coin_spend.coin]
            inner_wallet = inner_wallets[coin_spend.coin]
            # Get a list of the actions that each wallet supports
            outer_action_parsers = outer_wallet.get_outer_actions()
            inner_action_parsers = inner_wallet.get_inner_actions()

            next_coin: Coin = spend_group[0 if i == len(spend_group) - 1 else i + 1].coin

            # Make an announcement for the previous coin and assert the next coin's announcement
            make_announcement = MakeAnnouncement("coin", Program.to(nonce))
            assert_announcement = AssertAnnouncement("coin", next_coin.name(), Program.to(nonce))

            if make_announcement.name() in outer_action_parsers:
                new_outer_actions = [*outer_actions[coin_spend.coin], make_announcement]
                new_inner_actions = inner_actions[coin_spend.coin]
            elif make_announcement.name() in inner_action_parsers:
                new_outer_actions = outer_actions[coin_spend.coin]
                new_inner_actions = [*inner_actions[coin_spend.coin], make_announcement]
            else:
                raise ValueError(f"Bundle cannot be secured because coin: {coin_spend.coin} can't make announcements")

            if assert_announcement.name() in outer_action_parsers:
                new_outer_actions = [*new_outer_actions, assert_announcement]
                new_inner_actions = new_inner_actions
            elif assert_announcement.name() in inner_action_parsers:
                new_outer_actions = new_outer_actions
                new_inner_actions = [*new_inner_actions, assert_announcement]
            else:
                raise ValueError(f"Bundle cannot be secured because coin: {coin_spend.coin} can't assert announcements")

            # Let the outer wallet potentially modify the actions (for example, adding hints to payments)
            new_outer_actions, new_inner_actions = await outer_wallet.check_and_modify_actions(
                coin_spend.coin, new_outer_actions, new_inner_actions
            )
            # Double check that the new inner actions are still okay with the inner wallet
            for inner_action in new_inner_actions:
                if inner_action.name() not in inner_action_parsers:
                    coin_spends_after_announcements.append(coin_spend)
                    continue

            inner_solution = await inner_wallet.construct_inner_solution(new_inner_actions)
            outer_solution = await outer_wallet.construct_outer_solution(new_outer_actions, inner_solution)

            coin_spends_after_announcements.append(dataclasses.replace(coin_spend, solution=outer_solution))

        previous_actions = coin_spends_after_announcements

    return previous_actions


@dataclass(frozen=True)
class WalletActions:
    request: Solver
    bundle: SpendBundle
