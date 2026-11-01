from __future__ import annotations
import os,threading
import pytest
from encryption_tool.crypto import decrypt_data,decrypt_data_with_key,encrypt_data,encrypt_data_with_key
from encryption_tool.keys import generate_key,key_fingerprint,load_key
from encryption_tool.streaming import OperationCancelled,decrypt_file,encrypt_file,inspect_file
from encryption_tool.utilities import generate_passphrase,hash_file,hmac_bytes,verify_hmac
from encryption_tool.batch import batch_encrypt

def test_password_and_raw_key_roundtrip():
    p=encrypt_data(b"hello","secret");assert decrypt_data(p,"secret")==b"hello"
    key=os.urandom(32);p=encrypt_data_with_key(b"binary\0data",key);assert decrypt_data_with_key(p,key)==b"binary\0data"

def test_streaming_and_inspection(tmp_path):
    src,enc,out=tmp_path/"source",tmp_path/"data.etfs",tmp_path/"out";src.write_bytes(os.urandom(100000));updates=[]
    encrypt_file(src,enc,"pass",chunk_size=4096,progress=lambda n,t:updates.append((n,t)))
    assert updates and updates[-1][0]==updates[-1][1];assert inspect_file(enc)["format"]=="ETFS"
    decrypt_file(enc,out,"pass");assert out.read_bytes()==src.read_bytes()

def test_cancel_discards_temp(tmp_path):
    src,dst=tmp_path/"source",tmp_path/"target";src.write_bytes(os.urandom(50000));event=threading.Event();event.set()
    with pytest.raises(OperationCancelled):encrypt_file(src,dst,"pass",chunk_size=4096,cancel=event)
    assert not dst.exists()

def test_key_and_hmac(tmp_path):
    path=generate_key(tmp_path/"key");key=load_key(path);assert len(key)==32 and len(key_fingerprint(key))==64
    tag=hmac_bytes(b"data",key);assert verify_hmac(b"data",key,tag);assert not verify_hmac(b"other",key,tag)

def test_hash_and_password(tmp_path):
    path=tmp_path/"file";path.write_bytes(b"abc")
    assert hash_file(path)=="ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
    assert len(generate_passphrase(40))==40

def test_batch(tmp_path):
    src=tmp_path/"source";src.mkdir();(src/"a").write_bytes(b"a");(src/"b").write_bytes(b"b")
    result=batch_encrypt(src.iterdir(),tmp_path/"out","pass");assert len(result.completed)==2 and not result.failed
