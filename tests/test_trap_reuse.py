import pytest

from jaraco.context import ExceptionTrap


def test_reused_trap_reports_the_latest_context() -> None:
    trap = ExceptionTrap((ValueError,))
    with trap:
        raise ValueError('first failure')
    assert trap
    assert isinstance(trap.value, ValueError)

    with trap:
        assert not trap
        assert trap.value is None
        assert trap.tb is None
    assert not trap

    with trap:
        raise ValueError('second failure')
    assert trap
    assert str(trap.value) == 'second failure'


def test_unmatched_exception_does_not_retain_an_earlier_match() -> None:
    trap = ExceptionTrap((ValueError,))
    with trap:
        raise ValueError('first failure')
    with pytest.raises(TypeError, match='unmatched'), trap:
        raise TypeError('unmatched')
    assert not trap
    assert trap.value is None
    assert trap.tb is None
