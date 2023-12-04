from __future__ import annotations

import dataclasses
from typing import List

import pytest
from chia_rs import G1Element

from chia.types.blockchain_format.coin import Coin as ConsensusCoin
from chia.types.blockchain_format.program import Program
from chia.types.blockchain_format.sized_bytes import bytes32
from chia.types.coin_spend import CoinSpend
from chia.util.ints import uint64
from chia.util.streamable import ConversionError, Streamable, streamable
from chia.wallet.conditions import AggSigMe
from chia.wallet.util.blind_signer_tl import (
    BLIND_SIGNER_TRANSPORT,
    BSTLPathHint,
    BSTLSigningInstructions,
    BSTLSigningResponse,
    BSTLSigningTarget,
    BSTLSumHint,
)
from chia.wallet.util.signer_protocol import (
    ClvmStreamable,
    Coin,
    KeyHints,
    PathHint,
    SigningInstructions,
    SigningResponse,
    SigningTarget,
    Spend,
    SumHint,
    TransactionInfo,
    TransportLayer,
    TransportLayerMapping,
    UnsignedTransaction,
    clvm_serialization_mode,
)


def test_signing_lifecycle() -> None:
    pubkey: G1Element = G1Element()
    message: bytes = b"message"

    coin: ConsensusCoin = ConsensusCoin(bytes32([0] * 32), bytes32([0] * 32), uint64(0))
    puzzle: Program = Program.to(1)
    solution: Program = Program.to([AggSigMe(pubkey, message).to_program()])

    coin_spend: CoinSpend = CoinSpend(coin, puzzle, solution)
    assert Spend.from_coin_spend(coin_spend).as_coin_spend() == coin_spend

    tx: UnsignedTransaction = UnsignedTransaction(
        TransactionInfo([Spend.from_coin_spend(coin_spend)]),
        SigningInstructions(
            KeyHints([], []),
            [SigningTarget(bytes(pubkey), message, bytes32([1] * 32))],
        ),
    )

    assert tx == UnsignedTransaction.from_program(Program.from_bytes(bytes(tx.as_program())))

    as_json_dict = {
        "coin": {
            "parent_coin_id": "0x" + tx.transaction_info.spends[0].coin.parent_coin_id.hex(),
            "puzzle_hash": "0x" + tx.transaction_info.spends[0].coin.puzzle_hash.hex(),
            "amount": tx.transaction_info.spends[0].coin.amount,
        },
        "puzzle": "0x" + bytes(tx.transaction_info.spends[0].puzzle).hex(),
        "solution": "0x" + bytes(tx.transaction_info.spends[0].solution).hex(),
    }
    assert tx.transaction_info.spends[0].to_json_dict() == as_json_dict

    # Test from_json_dict with the special case where it encounters the as_program serialization in the middle of JSON
    assert tx.transaction_info.spends[0] == Spend.from_json_dict(
        {
            "coin": bytes(tx.transaction_info.spends[0].coin.as_program()).hex(),
            "puzzle": bytes(tx.transaction_info.spends[0].puzzle).hex(),
            "solution": bytes(tx.transaction_info.spends[0].solution).hex(),
        }
    )

    # Test the optional serialization as blobs
    with clvm_serialization_mode(True):
        assert (
            tx.transaction_info.spends[0].to_json_dict()
            == bytes(tx.transaction_info.spends[0].as_program()).hex()  # type: ignore[comparison-overlap]
        )

    # Make sure it's still a dict if using a Streamable object
    @streamable
    @dataclasses.dataclass(frozen=True)
    class TempStreamable(Streamable):
        streamable_key: Spend

    with clvm_serialization_mode(True):
        assert TempStreamable(tx.transaction_info.spends[0]).to_json_dict() == {
            "streamable_key": bytes(tx.transaction_info.spends[0].as_program()).hex()
        }

    with clvm_serialization_mode(False):
        assert TempStreamable(tx.transaction_info.spends[0]).to_json_dict() == {"streamable_key": as_json_dict}

    with clvm_serialization_mode(False):
        assert TempStreamable(tx.transaction_info.spends[0]).to_json_dict() == {"streamable_key": as_json_dict}
        with clvm_serialization_mode(True):
            assert TempStreamable(tx.transaction_info.spends[0]).to_json_dict() == {
                "streamable_key": bytes(tx.transaction_info.spends[0].as_program()).hex()
            }
            with clvm_serialization_mode(False):
                assert TempStreamable(tx.transaction_info.spends[0]).to_json_dict() == {"streamable_key": as_json_dict}

    streamable_blob = bytes(tx.transaction_info.spends[0])
    with clvm_serialization_mode(True):
        clvm_streamable_blob = bytes(tx.transaction_info.spends[0])

    assert streamable_blob != clvm_streamable_blob
    Spend.from_bytes(streamable_blob)
    Spend.from_bytes(clvm_streamable_blob)
    assert Spend.from_bytes(streamable_blob) == Spend.from_bytes(clvm_streamable_blob) == tx.transaction_info.spends[0]

    with clvm_serialization_mode(False):
        assert bytes(tx.transaction_info.spends[0]) == streamable_blob

    inside_streamable_blob = bytes(TempStreamable(tx.transaction_info.spends[0]))
    with clvm_serialization_mode(True):
        inside_clvm_streamable_blob = bytes(TempStreamable(tx.transaction_info.spends[0]))

    assert inside_streamable_blob != inside_clvm_streamable_blob
    assert (
        TempStreamable.from_bytes(inside_streamable_blob)
        == TempStreamable.from_bytes(inside_clvm_streamable_blob)
        == TempStreamable(tx.transaction_info.spends[0])
    )

    # Test some json loading errors

    with pytest.raises(ConversionError):
        Spend.from_json_dict("blah")
    with pytest.raises(ConversionError):
        UnsignedTransaction.from_json_dict(streamable_blob.hex())


class FooSpend(ClvmStreamable):
    coin: Coin
    blah: Program
    blah_also: Program = dataclasses.field(metadata=dict(key="solution"))

    @staticmethod
    def from_wallet_api(_from: Spend) -> FooSpend:
        return FooSpend(
            _from.coin,
            _from.puzzle,
            _from.solution,
        )

    @staticmethod
    def to_wallet_api(_from: FooSpend) -> Spend:
        return Spend(
            _from.coin,
            _from.blah,
            _from.blah_also,
        )


def test_transport_layer() -> None:
    FOO_TRANSPORT = TransportLayer(
        [
            TransportLayerMapping(
                Spend,
                FooSpend,
                FooSpend.from_wallet_api,
                FooSpend.to_wallet_api,
            )
        ]
    )

    spend = Spend(
        Coin(bytes32([0] * 32), bytes32([0] * 32), uint64(0)),
        Program.to(1),
        Program.to([]),
    )

    with clvm_serialization_mode(True):
        spend_bytes = bytes(spend)

    spend_program = Program.from_bytes(spend_bytes)
    assert spend_program.at("ff") == Program.to("coin")
    assert spend_program.at("rff") == Program.to("puzzle")
    assert spend_program.at("rrff") == Program.to("solution")

    with clvm_serialization_mode(True, FOO_TRANSPORT):
        foo_spend_bytes = bytes(spend)
        assert foo_spend_bytes.hex() == spend.to_json_dict()  # type: ignore[comparison-overlap]
        assert spend == Spend.from_bytes(foo_spend_bytes)
        assert spend == Spend.from_json_dict(foo_spend_bytes.hex())

    # Deserialization should only work now if using the transport layer
    with pytest.raises(Exception):
        Spend.from_bytes(foo_spend_bytes)
    with pytest.raises(Exception):
        Spend.from_json_dict(foo_spend_bytes.hex())

    assert foo_spend_bytes != spend_bytes
    foo_spend_program = Program.from_bytes(foo_spend_bytes)
    assert foo_spend_program.at("ff") == Program.to("coin")
    assert foo_spend_program.at("rff") == Program.to("blah")
    assert foo_spend_program.at("rrff") == Program.to("solution")


def test_blind_signer_transport_layer() -> None:
    sum_hints: List[SumHint] = [SumHint([b"a", b"b", b"c"], b"offset"), SumHint([b"c", b"b", b"a"], b"offset2")]
    path_hints: List[PathHint] = [
        PathHint(b"root1", [uint64(1), uint64(2), uint64(3)]),
        PathHint(b"root2", [uint64(4), uint64(5), uint64(6)]),
    ]
    signing_targets: List[SigningTarget] = [
        SigningTarget(b"pubkey", b"message", bytes32([0] * 32)),
        SigningTarget(b"pubkey2", b"message2", bytes32([1] * 32)),
    ]

    instructions: SigningInstructions = SigningInstructions(
        KeyHints(sum_hints, path_hints),
        signing_targets,
    )
    signing_response: SigningResponse = SigningResponse(
        b"signature",
        bytes32([1] * 32),
    )

    bstl_sum_hints: List[BSTLSumHint] = [
        BSTLSumHint([b"a", b"b", b"c"], b"offset"),
        BSTLSumHint([b"c", b"b", b"a"], b"offset2"),
    ]
    bstl_path_hints: List[BSTLPathHint] = [
        BSTLPathHint(b"root1", [uint64(1), uint64(2), uint64(3)]),
        BSTLPathHint(b"root2", [uint64(4), uint64(5), uint64(6)]),
    ]
    bstl_signing_targets: List[BSTLSigningTarget] = [
        BSTLSigningTarget(b"pubkey", b"message", bytes32([0] * 32)),
        BSTLSigningTarget(b"pubkey2", b"message2", bytes32([1] * 32)),
    ]

    bstl_instructions: BSTLSigningInstructions = BSTLSigningInstructions(
        bstl_sum_hints,
        bstl_path_hints,
        bstl_signing_targets,
    )
    bstl_signing_response: BSTLSigningResponse = BSTLSigningResponse(
        b"signature",
        bytes32([1] * 32),
    )
    with clvm_serialization_mode(True, None):
        bstl_instructions_bytes = bytes(bstl_instructions)
        bstl_signing_response_bytes = bytes(bstl_signing_response)

    with clvm_serialization_mode(True, BLIND_SIGNER_TRANSPORT):
        instructions_bytes = bytes(instructions)
        signing_response_bytes = bytes(signing_response)
        assert instructions_bytes == bstl_instructions_bytes == bytes(bstl_instructions)
        assert signing_response_bytes == bstl_signing_response_bytes == bytes(bstl_signing_response)

    # Deserialization should only work now if using the transport layer
    with pytest.raises(Exception):
        SigningInstructions.from_bytes(instructions_bytes)
    with pytest.raises(Exception):
        SigningResponse.from_bytes(signing_response_bytes)

    assert BSTLSigningInstructions.from_bytes(instructions_bytes) == bstl_instructions
    assert BSTLSigningResponse.from_bytes(signing_response_bytes) == bstl_signing_response
    with clvm_serialization_mode(True, BLIND_SIGNER_TRANSPORT):
        assert SigningInstructions.from_bytes(instructions_bytes) == instructions
        assert SigningResponse.from_bytes(signing_response_bytes) == signing_response

    assert Program.from_bytes(instructions_bytes).at("ff") == Program.to("s")
    assert Program.from_bytes(signing_response_bytes).at("ff") == Program.to("s")
