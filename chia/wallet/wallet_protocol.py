from __future__ import annotations

from typing import TYPE_CHECKING, Any, List, Optional, Set

from blspy import G1Element, G2Element
from typing_extensions import Protocol

from chia.server.ws_connection import WSChiaConnection
from chia.types.blockchain_format.coin import Coin
from chia.types.blockchain_format.program import Program
from chia.types.blockchain_format.sized_bytes import bytes32
from chia.types.coin_spend import CoinSpend
from chia.util.ints import uint8, uint32, uint64, uint128
from chia.wallet.puzzle_drivers import Solver
from chia.wallet.trading.wallet_actions import WalletAction
from chia.wallet.wallet_coin_record import WalletCoinRecord

if TYPE_CHECKING:
    from chia.wallet.wallet_state_manager import WalletStateManager


class WalletProtocol(Protocol):

    # TODO: it seems like this should return WalletType instead
    @classmethod
    def type(cls) -> uint8:
        ...

    def id(self) -> uint32:
        ...

    async def coin_added(self, coin: Coin, height: uint32, peer: WSChiaConnection) -> None:
        ...

    async def select_coins(
        self,
        amount: uint64,
        exclude: Optional[List[Coin]] = None,
        min_coin_amount: Optional[uint64] = None,
        max_coin_amount: Optional[uint64] = None,
    ) -> Set[Coin]:
        ...

    async def get_confirmed_balance(self, record_list: Optional[Set[WalletCoinRecord]] = None) -> uint128:
        ...

    async def get_unconfirmed_balance(self, unspent_records: Optional[Set[WalletCoinRecord]] = None) -> uint128:
        ...

    async def get_spendable_balance(self, unspent_records: Optional[Set[WalletCoinRecord]] = None) -> uint128:
        ...

    async def get_pending_change_balance(self) -> uint64:
        ...

    async def get_max_send_amount(self, records: Optional[Set[WalletCoinRecord]] = None) -> uint128:
        ...

    # not all wallet supports this. To signal support, make
    # require_derivation_paths() return true
    def puzzle_hash_for_pk(self, pubkey: G1Element) -> bytes32:
        ...

    def require_derivation_paths(self) -> bool:
        ...

    def get_wallet_actions(self) -> List[WalletAction]:
        ...

    # WalletStateManager is only imported for type hinting thus leaving pylint
    # unable to process this
    wallet_state_manager: WalletStateManager  # pylint: disable=used-before-assignment


class InnerWallet(Protocol):
    async def solve_for_dependencies(
        self,
        coin: Coin,
        unwrapped_puzzle_hash: bytes32,
        dependencies: List[SpendDependency],
        solver: Solver,
    ) -> Tuple[Program, Program, G2Element]:
        ...


class OuterWallet(Protocol):
    async def get_inner_wallet(self, coin: Coin) -> InnerWallet:
        # TODO: If we ever have more inner wallets, this will need to be more complicated
        return self
