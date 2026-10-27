from typing import Literal

import pytest

from jaraco.context import on_interrupt


class Interrupt(KeyboardInterrupt):
    pass


class NestedInterrupt(Interrupt):
    pass


def capture(
    action: Literal['error', 'suppress', 'ignore'], interrupt: KeyboardInterrupt
) -> BaseException | None:
    try:
        with on_interrupt(action, code=255):
            raise interrupt
    except (KeyboardInterrupt, SystemExit) as error:
        return error
    return None


@pytest.mark.parametrize('exc_type', [KeyboardInterrupt, Interrupt, NestedInterrupt])
def test_error(exc_type: type[KeyboardInterrupt]) -> None:
    interrupt = exc_type('stopped')
    caught = capture('error', interrupt)
    assert isinstance(caught, SystemExit)
    assert caught.code == 255
    assert caught.__cause__ is interrupt


@pytest.mark.parametrize('exc_type', [KeyboardInterrupt, Interrupt, NestedInterrupt])
def test_suppress(exc_type: type[KeyboardInterrupt]) -> None:
    assert capture('suppress', exc_type()) is None


@pytest.mark.parametrize('exc_type', [KeyboardInterrupt, Interrupt, NestedInterrupt])
def test_ignore(exc_type: type[KeyboardInterrupt]) -> None:
    interrupt = exc_type()
    assert capture('ignore', interrupt) is interrupt


@pytest.mark.parametrize('action', ['error', 'suppress', 'ignore'])
def test_other_exception(action: Literal['error', 'suppress', 'ignore']) -> None:
    error = ValueError('unrelated')
    with pytest.raises(ValueError) as caught, on_interrupt(action):
        raise error
    assert caught.value is error
    with on_interrupt(action):
        pass


def test_decorator() -> None:
    @on_interrupt('error', code=42)
    def interrupted() -> None:
        raise Interrupt()

    with pytest.raises((KeyboardInterrupt, SystemExit)) as caught:
        interrupted()
    assert isinstance(caught.value, SystemExit)
    assert caught.value.code == 42
