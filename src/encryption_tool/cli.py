from __future__ import annotations
import argparse,getpass,sys
from pathlib import Path
from encryption_tool.batch import batch_decrypt,batch_encrypt
from encryption_tool.config import config_path,write_default_config
from encryption_tool.crypto import decrypt_data,encrypt_data,decrypt_data_with_key,encrypt_data_with_key
from encryption_tool.keys import generate_key,inspect_key,load_key
from encryption_tool.streaming import decrypt_directory,decrypt_file,encrypt_directory,encrypt_file,inspect_file
from encryption_tool.utilities import HASH_ALGORITHMS,generate_passphrase,hash_file,hmac_bytes,verify_hmac
def password(confirm:bool=False)->str:
    value=getpass.getpass("Password: ")
    if confirm and value!=getpass.getpass("Confirm password: "):raise ValueError("Passwords do not match.")
    return value
def parser()->argparse.ArgumentParser:
    p=argparse.ArgumentParser(prog="encrypt-tool");s=p.add_subparsers(dest="cmd",required=True)
    for name in ("encrypt","decrypt","encrypt-dir","decrypt-dir","batch-encrypt","batch-decrypt"):
        q=s.add_parser(name);q.add_argument("source",type=Path);q.add_argument("destination",type=Path);q.add_argument("--overwrite",action="store_true")
        if name in ("encrypt","encrypt-dir","batch-encrypt"):q.add_argument("--algorithm",choices=("AES-256-GCM","ChaCha20-Poly1305"),default="AES-256-GCM")
    for name in ("encrypt-key","decrypt-key"):
        q=s.add_parser(name);q.add_argument("source",type=Path);q.add_argument("destination",type=Path);q.add_argument("--key",required=True,type=Path)
        if name=="encrypt-key":q.add_argument("--algorithm",choices=("AES-256-GCM","ChaCha20-Poly1305"),default="AES-256-GCM")
    q=s.add_parser("hash");q.add_argument("source",type=Path);q.add_argument("--algorithm",choices=HASH_ALGORITHMS,default="sha256")
    q=s.add_parser("inspect");q.add_argument("source",type=Path)
    q=s.add_parser("keygen");q.add_argument("destination",type=Path)
    q=s.add_parser("key-info");q.add_argument("source",type=Path)
    q=s.add_parser("password");q.add_argument("--length",type=int,default=32)
    q=s.add_parser("hmac");q.add_argument("source",type=Path);q.add_argument("--key",required=True,type=Path);q.add_argument("--algorithm",choices=("sha256","sha512"),default="sha256")
    q=s.add_parser("verify-hmac");q.add_argument("source",type=Path);q.add_argument("tag");q.add_argument("--key",required=True,type=Path);q.add_argument("--algorithm",choices=("sha256","sha512"),default="sha256")
    s.add_parser("init-config")
    return p
def main()->int:
    a=parser().parse_args()
    try:
        if a.cmd=="encrypt":print(encrypt_file(a.source,a.destination,password(True),a.algorithm,overwrite=a.overwrite))
        elif a.cmd=="decrypt":print(decrypt_file(a.source,a.destination,password(),overwrite=a.overwrite))
        elif a.cmd=="encrypt-dir":print(*encrypt_directory(a.source,a.destination,password(),a.algorithm,a.overwrite),sep="\n")
        elif a.cmd=="decrypt-dir":print(*decrypt_directory(a.source,a.destination,password(),a.overwrite),sep="\n")
        elif a.cmd=="batch-encrypt":print(batch_encrypt(a.source.iterdir(),a.destination,password(),a.algorithm,a.overwrite))
        elif a.cmd=="batch-decrypt":print(batch_decrypt(a.source.glob("*.etfs"),a.destination,password(),a.overwrite))
        elif a.cmd=="encrypt-key":
            data=a.source.read_bytes();out=encrypt_data_with_key(data,load_key(a.key),a.algorithm)
            a.destination.parent.mkdir(parents=True,exist_ok=True)
            with a.destination.open("xb") as f:f.write(out)
            print(a.destination)
        elif a.cmd=="decrypt-key":
            data=decrypt_data_with_key(a.source.read_bytes(),load_key(a.key))
            with a.destination.open("xb") as f:f.write(data)
            print(a.destination)
        elif a.cmd=="hash":print(hash_file(a.source,a.algorithm))
        elif a.cmd=="inspect":print(inspect_file(a.source))
        elif a.cmd=="keygen":print(generate_key(a.destination))
        elif a.cmd=="key-info":print(inspect_key(a.source))
        elif a.cmd=="password":print(generate_passphrase(a.length))
        elif a.cmd=="hmac":print(hmac_bytes(a.source.read_bytes(),load_key(a.key),a.algorithm))
        elif a.cmd=="verify-hmac":print("VALID" if verify_hmac(a.source.read_bytes(),load_key(a.key),a.tag,a.algorithm) else "INVALID")
        elif a.cmd=="init-config":print(write_default_config(config_path()))
        return 0
    except (OSError,ValueError,RuntimeError) as exc:
        print(f"error: {exc}",file=sys.stderr);return 1
if __name__=="__main__":raise SystemExit(main())
