from dataclasses import dataclass
from typing import List, Optional, Protocol, TypeVar

from clvm_tools.binutils import disassemble

from chia.types.announcement import Announcement
from chia.types.blockchain_format.program import Program
from chia.types.blockchain_format.sized_bytes import bytes32
from chia.util.hash import std_hash
from chia.util.ints import uint64
from chia.wallet.payment import Payment
from chia.wallet.puzzle_drivers import cast_to_int, Solver
from chia.wallet.trading.offer import ADD_WRAPPED_ANNOUNCEMENT, CURRY, OFFER_MOD, OFFER_MOD_HASH
from chia.wallet.trading.wallet_actions import Condition, Graftroot, WalletAction
from chia.wallet.puzzles.puzzle_utils import (
    make_assert_coin_announcement,
    make_assert_puzzle_announcement,
    make_create_coin_announcement,
    make_create_coin_condition,
    make_create_puzzle_announcement,
    make_reserve_fee_condition,
)


class ActionAlias(Protocol):
    @staticmethod
    def name() -> str:
        ...

    @classmethod
    def from_solver(cls, solver: Solver) -> "ActionAlias":
        ...

    def to_solver(self) -> Solver:
        ...

    def de_alias(self) -> WalletAction:
        ...

    @staticmethod
    def action_name() -> str:
        ...

    @classmethod
    def from_action(cls, action: WalletAction) -> "ActionAlias":
        ...


_T_DirectPayment = TypeVar("_T_DirectPayment", bound="DirectPayment")


@dataclass(frozen=True)
class DirectPayment:
    payment: Payment
    hints: List[bytes]

    @staticmethod
    def name() -> str:
        return "direct_payment"

    @classmethod
    def from_solver(cls, solver: Solver) -> _T_DirectPayment:
        payment = solver["payment"]
        return cls(
            Payment(payment["puzhash"], cast_to_int(payment["amount"]), payment["memos"] if "memos" in payment else []),
            payment["hints"] if "hints" in payment else [],
        )

    def to_solver(self) -> Solver:
        return Solver(
            {
                "type": self.name(),
                "payment": {
                    "puzhash": "0x" + self.payment.puzzle_hash.hex(),
                    "amount": str(self.payment.amount),
                    "hints": ["0x" + hint.hex() for hint in self.hints],
                    "memos": ["0x" + memo.hex() for memo in self.payment.memos],
                },
            }
        )

    def de_alias(self) -> WalletAction:
        return Condition(
            Program.to(
                make_create_coin_condition(
                    self.payment.puzzle_hash, self.payment.amount, [*self.hints, *self.payment.memos]
                )
            )
        )

    @staticmethod
    def action_name() -> str:
        return Condition.name()

    @classmethod
    def from_action(cls, action: WalletAction) -> _T_DirectPayment:
        if action.name() != Condition.name():
            raise ValueError("Can only parse a DirectPayment from Condition")

        puzzle_hash: bytes32 = bytes32(action.condition.at("rf").as_python())
        if action.condition.first() != Program.to(51) or puzzle_hash == OFFER_MOD_HASH:
            raise ValueError("Tried to parse a condition that was not a direct payment")

        memos: List[bytes] = (
            action.condition.at("rrrf").as_python() if action.condition.at("rrr") != Program.to(None) else []
        )

        return cls(
            Payment(puzzle_hash, uint64(action.condition.at("rrf").as_int()), memos),
            [],
        )

    def augment(self, environment: Solver) -> _T_DirectPayment:
        return self


_T_OfferedAmount = TypeVar("_T_OfferedAmount", bound="OfferedAmount")


@dataclass(frozen=True)
class OfferedAmount:
    amount: int

    @staticmethod
    def name() -> str:
        return "offered_amount"

    @classmethod
    def from_solver(cls, solver: Solver) -> _T_OfferedAmount:
        return cls(cast_to_int(solver["amount"]))

    def to_solver(self) -> Solver:
        return Solver(
            {
                "type": self.name(),
                "amount": str(self.amount),
            }
        )

    def de_alias(self) -> List[Program]:
        return Condition(Program.to(make_create_coin_condition(OFFER_MOD_HASH, self.amount, [])))

    @staticmethod
    def action_name() -> str:
        return Condition.name()

    @classmethod
    def from_action(cls, action: WalletAction) -> _T_OfferedAmount:
        if action.name() != Condition.name():
            raise ValueError("Can only parse a OfferedAmount from Condition")

        puzzle_hash: bytes32 = bytes32(action.condition.at("rf").as_python())
        if puzzle_hash != OFFER_MOD_HASH:
            raise ValueError("Tried to parse a condition that was not an offer payment")

        return cls(action.condition.at("rrf").as_int())

    def augment(self, environment: Solver) -> _T_OfferedAmount:
        return self


_T_Fee = TypeVar("_T_Fee", bound="Fee")


@dataclass(frozen=True)
class Fee:
    amount: int

    @staticmethod
    def name() -> str:
        return "fee"

    @classmethod
    def from_solver(cls, solver: Solver) -> _T_Fee:
        return cls(cast_to_int(solver["amount"]))

    def to_solver(self) -> Solver:
        return Solver(
            {
                "type": self.name(),
                "amount": str(self.amount),
            }
        )

    def de_alias(self) -> List[Program]:
        return Condition(Program.to(make_reserve_fee_condition(self.amount)))

    @staticmethod
    def action_name() -> str:
        return Condition.name()

    @classmethod
    def from_action(cls, action: WalletAction) -> _T_Fee:
        if action.name() != Condition.name():
            raise ValueError("Can only parse a Fee from Condition")

        if action.condition.first() != Program.to(52):
            raise ValueError("Tried to parse a condition that was not a RESERVE_FEE")

        return cls(action.condition.at("rf").as_int())

    def augment(self, environment: Solver) -> _T_Fee:
        return self


_T_MakeAnnouncement = TypeVar("_T_MakeAnnouncement", bound="MakeAnnouncement")


@dataclass(frozen=True)
class MakeAnnouncement:
    type: str
    data: Program

    @staticmethod
    def name() -> str:
        return "make_announcement"

    def __post_init__(self) -> None:
        if self.type not in ["coin", "puzzle"]:
            raise ValueError(f"Invalid announcement type {self.type}")

    @classmethod
    def from_solver(cls, solver: Solver) -> _T_MakeAnnouncement:
        return cls(solver["announcement_type"], Program.to(solver["announcement_data"]))

    def to_solver(self) -> Solver:
        return Solver(
            {
                "type": self.name(),
                "announcement_type": self.type,
                "announcement_data": disassemble(self.data),
            }
        )

    def de_alias(self) -> List[Program]:
        if self.type == "puzzle":
            return Condition(Program.to(make_create_puzzle_announcement(self.data)))
        elif self.type == "coin":
            return Condition(Program.to(make_create_coin_announcement(self.data)))
        else:
            raise ValueError("Invalid announcement type")

    @staticmethod
    def action_name() -> str:
        return Condition.name()

    @classmethod
    def from_action(cls, action: WalletAction) -> _T_MakeAnnouncement:
        if action.name() != Condition.name():
            raise ValueError("Can only parse a MakeAnnouncement from Condition")

        if action.condition.first() not in (Program.to(60), Program.to(62)):
            raise ValueError("Tried to parse a condition that was not a CREATE_*_ANNOUNCEMENT")

        return cls("coin" if action.condition.first() == Program.to(60) else "puzzle", action.condition.at("rf"))

    def augment(self, environment: Solver) -> _T_MakeAnnouncement:
        return self


_T_AssertAnnouncement = TypeVar("_T_AssertAnnouncement", bound="AssertAnnouncement")


@dataclass(frozen=True)
class AssertAnnouncement:
    type: str
    data: bytes
    origin: Optional[bytes32] = None

    @staticmethod
    def name() -> str:
        return "assert_announcement"

    def __post_init__(self) -> None:
        if self.type not in ["coin", "puzzle"]:
            raise ValueError(f"Invalid announcement type {self.type}")

    @classmethod
    def from_solver(cls, solver: Solver) -> _T_AssertAnnouncement:
        if "origin" in solver:
            data = solver["announcement_data"]
            origin = bytes32(solver["origin"])
        else:
            data = bytes32(solver["announcement_data"])
            origin = None
        return cls(solver["announcement_type"], data, origin)

    def to_solver(self) -> Solver:
        if self.origin is not None:
            origin_dict = {
                "origin": "0x" + self.origin.hex(),
            }
        else:
            origin_dict = {}
        return Solver(
            {
                **{
                    "type": self.name(),
                    "announcement_type": self.type,
                    "announcement_data": "0x" + self.data.hex(),
                },
                **origin_dict,
            }
        )

    def de_alias(self) -> List[Program]:
        data: bytes32 = bytes32(self.data) if self.origin is None else std_hash(self.origin + self.data)
        if self.type == "puzzle":
            return Condition(Program.to(make_assert_puzzle_announcement(data)))
        elif self.type == "coin":
            return Condition(Program.to(make_assert_coin_announcement(data)))
        else:
            raise ValueError("Invalid announcement type")

    @staticmethod
    def action_name() -> str:
        return Condition.name()

    @classmethod
    def from_action(cls, action: WalletAction) -> _T_AssertAnnouncement:
        if action.name() != Condition.name():
            raise ValueError("Can only parse a AssertAnnouncement from Condition")

        if action.condition.first() not in (Program.to(61), Program.to(63)):
            raise ValueError("Tried to parse a condition that was not an ASSERT_*_ANNOUNCEMENT")

        return cls(
            "coin" if action.condition.first() == Program.to(61) else "puzzle", action.condition.at("rf").as_python()
        )

    def augment(self, environment: Solver) -> _T_AssertAnnouncement:
        return self


_T_RequestPayment = TypeVar("_T_RequestPayment", bound="RequestPayment")


@dataclass(frozen=True)
class RequestPayment:
    asset_types: List[Solver]
    nonce: Optional[bytes32]
    payments: List[Payment]

    @staticmethod
    def name() -> str:
        return "request_payment"

    @classmethod
    def from_solver(cls, solver: Solver) -> _T_RequestPayment:
        return cls(
            solver["asset_types"],
            bytes32(solver["nonce"]) if "nonce" in solver else None,
            [Payment(bytes32(p["puzhash"]), cast_to_int(p["amount"]), p["memos"]) for p in solver["payments"]],
        )

    def to_solver(self) -> Solver:
        solver_dict: Dict[str, Any] = {
            "type": self.name(),
            "asset_types": self.asset_types,
            "payments": [
                {
                    "puzhash": "0x" + p.puzzle_hash.hex(),
                    "amount": str(p.amount),
                    "memos": ["0x" + memo.hex() for memo in p.memos],
                }
                for p in self.payments
            ],
        }
        if self.nonce is not None:
            solver_dict["nonce"] = "0x" + self.nonce.hex()
        return Solver(solver_dict)

    def de_alias(self) -> WalletAction:
        def walk_tree_and_hash_curried(tree: Program, template: Program) -> Program:
            if template.atom is None:
                return walk_tree_and_hash_curried(tree.first(), template.first()).cons(
                    walk_tree_and_hash_curried(tree.rest(), template.rest())
                )
            elif template == Program.to(1):
                return tree.get_tree_hash()
            else:
                return tree

        return Graftroot(
            self.construct_puzzle_wrapper(),
            Program.to(None),
            self.construct_metadata(),
        )

    def construct_metadata(self) -> Program:
        return Program.to(
            (
                (self.nonce, [p.as_condition_args() for p in self.payments]),
                [
                    [typ["mod"] for typ in self.asset_types],
                    [typ["solution_template"] for typ in self.asset_types],
                    [typ["committed_args"] for typ in self.asset_types],
                ],
            )
        )

    def construct_puzzle_wrapper(self) -> Program:
        if self.check_for_optimization():
            puzzle_reveal: Program = OFFER_MOD
            for typ in self.asset_types:
                puzzle_reveal = Program.to(
                    [
                        2,
                        (1, typ["mod"]),
                        RequestPayment.build_environment(
                            typ["solution_template"], typ["committed_args"], typ["committed_args"], puzzle_reveal
                        ),
                    ]
                )
            assertion: Program = Program.to(
                [
                    63,
                    Announcement(
                        puzzle_reveal.get_tree_hash(),
                        Program.to((self.nonce, [p.as_condition_args() for p in self.payments])).get_tree_hash(),
                    ).name(),
                ]
            )
            # (mod (inner_puz) (qq (c (q . assertion) (a (q . (unquote inner_puz)) 1))))
            # (c (q . 4) (c (q 1 . "assertion") (c (c (q . 2) (c (c (q . 1) 2) (q 1))) ())))
            return Program.to([4, (1, 4), [4, (1, (1, assertion)), [4, [4, (1, 2), [4, [4, (1, 1), 2], [1, 1]]], []]]])
        else:
            return CURRY.curry(
                ADD_WRAPPED_ANNOUNCEMENT.curry(
                    [bytes32(Program.to(typ["mod"]).get_tree_hash()) for typ in self.asset_types],
                    [typ["solution_template"] for typ in self.asset_types],
                    [
                        walk_tree_and_hash_curried(typ["committed_args"], typ["solution_template"])
                        for typ in self.asset_types
                    ],
                    OFFER_MOD_HASH,
                    Program.to((self.nonce, [p.as_condition_args() for p in self.payments])).get_tree_hash(),
                )
            )

    def construct_solution_wrapper(self, solved_args: List[Program]) -> Program:
        if self.check_for_optimization():
            return Program.to(2)
        else:
            return Graftroot(
                self.construct_puzzle_wrapper(),
                Program.to([4, 2, [1, solved_args]]),  # (c 2 (q solved_args))
                self.construct_metadata(),
            )

    def check_for_optimization(self) -> bool:
        """
        If we're specifically requesting asset types that are fully complete, we can simplify this graftroot down to the
        condition it will invariably produce
        """
        return not any(["-1" in typ["solution_template"] for typ in self.asset_types])

    @classmethod
    def build_environment(
        template: Program, committed_values: Program, solved_values: Program, puzzle_reveal: Program
    ) -> Program:
        if template.atom is None:
            return Program.to(
                [
                    4,
                    RequestPayment.build_environment(committed_values.first(), template.first(), solved_values.first()),
                    RequestPayment.build_environment(committed_values.rest(), template.rest(), solved_values.rest()),
                ]
            )
        elif template == Program.to(1):
            return Program.to((1, committed_values)).get_tree_hash()
        elif template == Program.to(-1):
            return Program.to((1, solved_values)).get_tree_hash()
        elif template == Program.to(0):
            return Program.to((1, puzzle_reveal))
        elif template == Program.to("$"):
            return Program.to(1)

    @staticmethod
    def action_name() -> str:
        return Graftroot.name()

    @classmethod
    def from_action(cls, action: WalletAction) -> _T_RequestPayment:
        if action.name() != Graftroot.name():
            raise ValueError("Can only parse a RequestPayment from Graftroot")

        nonce_and_payments = action.metadata.first()
        nonce: Optional[bytes32] = (
            None if nonce_and_payments.first() == Program.to(None) else bytes32(nonce_and_payments.first().as_python())
        )
        payments: List[Payment] = [
            Payment.from_condition(Program.to((51, condition))) for condition in nonce_and_payments.rest().as_iter()
        ]
        mods: Program = action.metadata.at("rf")
        solution_templates: Program = action.metadata.at("rrf")
        committed_args: Program = action.metadata.at("rrrf")
        asset_types: List[Solver] = [
            Solver(
                {
                    "mod": disassemble(mod),
                    "solution_template": disassemble(template),
                    "committed_args": disassemble(committed),
                }
            )
            for mod, template, committed in zip(mods.as_iter(), solution_templates.as_iter(), committed_args.as_iter())
        ]

        return cls(asset_types, nonce, payments)

    def augment(self, environment: Solver) -> WalletAction:
        if "payment_types" in environment:
            for payment_type in environment["payment_types"]:
                nonce: Optional[bytes32] = (
                    None
                    if "nonce" not in payment_type or payment_type["nonce"] == Program.to(None)
                    else bytes32(payment_type["nonce"])
                )
                payments: List[Payment] = [
                    Payment(bytes32(p["puzhash"]), cast_to_int(p["amount"]), p["memos"])
                    for p in payment_type["payments"]
                ]
                asset_types: List[Solver] = payment_type["asset_types"] if "asset_types" in payment else []
                if (
                    nonce == self.nonce
                    and set(payments) == set(self.payments)
                    and len(asset_types) == len(self.asset_types)
                ):
                    solved_args: List[Program] = []
                    for new_type, static_type in enumerate(asset_types, self.asset_types):
                        if new_type["mod"] == static_type["mod"]:
                            solved_args.append(new_type["solved_args"])
                        else:
                            break
                    else:
                        return Graftroot(
                            self.construct_puzzle_wrapper(),
                            # nothing specified means it will get optimized so it doesn't matter what we pass here
                            self.construct_solution_wrapper(solved_args),
                            self.construct_metadata(),
                        )
                    continue

        return Graftroot(
            self.construct_puzzle_wrapper(),
            # nothing specified means it will get optimized so it doesn't matter what we pass here
            self.construct_solution_wrapper([]),
            self.construct_metadata(),
        )
