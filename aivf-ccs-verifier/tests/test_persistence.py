import os, sys, tempfile
sys.path.insert(0, os.path.join(os.path.dirname(__file__),"..","src"))
from aivf_ccs_verifier import Command, Verifier, ReceiptManager, ReceiptValidationError, SQLiteStore

def run():
    with tempfile.TemporaryDirectory() as td:
        db=os.path.join(td,"evidence.db")
        key=os.path.join(td,"keys","ed25519.seed")
        store1=SQLiteStore(db)
        rm1=ReceiptManager(key_file=key,store=store1,issuer="urn:wwknow:aivf:verifier:test",audience="urn:wwknow:aivf:executor:test")
        v1=Verifier(receipt_manager=rm1,config={})
        cmd=Command(agent_id="a",tool="web_fetch",params={"url":"https://example.com"})
        r=v1.verify(cmd).receipt
        assert r["sequence"] == 1
        rm1.consume(r)
        assert store1.count_evidence() >= 2

        store2=SQLiteStore(db)
        rm2=ReceiptManager(key_file=key,store=store2,issuer="urn:wwknow:aivf:verifier:test",audience="urn:wwknow:aivf:executor:test")
        try:
            rm2.validate(r,expected_audience="urn:wwknow:aivf:executor:test",require_authorizing=True)
            raise AssertionError("replay state was not durable")
        except ReceiptValidationError:
            pass

        v2=Verifier(receipt_manager=rm2,config={})
        r2=v2.verify(Command(agent_id="a",tool="web_fetch",params={"url":"https://example.org"})).receipt
        assert r2["sequence"] == 2
        assert os.stat(key).st_mode & 0o077 == 0
        print("persistent key/replay/evidence test passed")

if __name__=="__main__":
    run()
