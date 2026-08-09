"""Judge keri-go's output with keripy's own validator.

The conformance suite proves that given keripy's inputs, keri-go reproduces
keripy's bytes. This asks the stricter question: does keripy ACCEPT what keri-go
produces? Byte comparison checks two strings against each other; acceptance runs
the reference implementation's validator — signature verification, chaining,
pre-rotation — over our output.

    go run ./interop | python interop/verify_interop.py

Exit status is non-zero if any message is refused, so this can gate a build.
"""

import base64
import json
import sys

from keri.core import eventing, parsing, serdering
from keri.db import basing


def main():
    messages = json.load(sys.stdin)
    accepted, refused = 0, 0

    with basing.openDB(name="interop") as db:
        kvy = eventing.Kevery(db=db, lax=True, local=True)
        for m in messages:
            raw = base64.b64decode(m["message_b64"])
            label = m["label"]
            try:
                parsing.Parser(kvy=kvy).parse(ims=bytearray(raw))
            except Exception as exc:  # noqa: BLE001 — report, do not mask
                print(f"  REFUSED  {label:26} {type(exc).__name__}: {exc}")
                refused += 1
                continue

            # The parser swallows validation failures, so acceptance is checked
            # by looking at what actually landed in the key log rather than by
            # the absence of an exception.
            event = base64.b64decode(m["event_b64"])
            serder = serdering.SerderKERI(raw=event)
            kever = kvy.kevers.get(serder.pre)
            if kever is None:
                print(f"  REFUSED  {label:26} nothing was established for {serder.pre}")
                refused += 1
            elif kever.serder.said != serder.said:
                print(f"  PARTIAL  {label:26} log is at {kever.serder.said}, "
                      f"this event is {serder.said}")
                refused += 1
            else:
                print(f"  accepted {label:26} sn={kever.sn} {serder.pre}")
                accepted += 1

    print(f"\n{accepted} accepted, {refused} refused, out of {len(messages)}")
    return 1 if refused else 0


if __name__ == "__main__":
    sys.exit(main())
