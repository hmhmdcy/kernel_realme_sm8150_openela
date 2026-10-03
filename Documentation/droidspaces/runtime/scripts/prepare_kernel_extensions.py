#!/usr/bin/env python3
"""Isolate and repair the existing nft_socket backport for this 4.14 API."""
import difflib
import hashlib
import json
from pathlib import Path
import shutil

ROOT = Path(__file__).resolve().parents[1]
BUILD = Path('/var/tmp/rmx1931-ksunext-cd739c788023')
SOURCE = BUILD / 'src'
TARGET = BUILD / 'src-ext-network'


def replace_once(text, before, after):
    if text.count(before) != 1:
        raise RuntimeError('Source no longer matches the audited baseline')
    return text.replace(before, after)


def main():
    expected = {}
    name = 'include/net/netfilter/nf_socket.h'
    before = (SOURCE / name).read_text()
    expected[name] = replace_once(before, '#define _NF_SOCK_H_\n',
        '#define _NF_SOCK_H_\n\n#include <net/inet_sock.h>\n#include <net/inet_timewait_sock.h>\n'
        '#include <net/request_sock.h>\n#include <net/tcp_states.h>\n')
    name = 'net/netfilter/nft_socket.c'
    before = (SOURCE / name).read_text()
    after = replace_once(before, 'switch(ctx->family)', 'switch(ctx->afi->family)')
    after = replace_once(after, '\tunion {\n\t\tenum nft_registers\tdreg:8;\n\t};', '\tu8\t\t\t\tdreg;')
    after = replace_once(after,
        '\tpriv->dreg = nft_parse_register(tb[NFTA_SOCKET_DREG]);\n'
        '\treturn nft_validate_register_store(ctx, priv->dreg, NULL,\n'
        '\t\t\t\t\t   NFT_DATA_VALUE, len);',
        '\treturn nft_parse_register_store(ctx, tb[NFTA_SOCKET_DREG], &priv->dreg,\n'
        '\t\t\t\t\tNULL, NFT_DATA_VALUE, len);')
    after = replace_once(after, '\tif (!sk)\n\t\tswitch(nft_pf(pkt))',
        '\tif (sk && !net_eq(nft_net(pkt), sock_net(sk)))\n\t\tsk = NULL;\n'
        '\tif (!sk)\n\t\tswitch(nft_pf(pkt))')
    after = replace_once(after, '\tif(!sk) {\n\t\tnft_reg_store8(dest, 0);',
        '\tif(!sk) {\n\t\tregs->verdict.code = NFT_BREAK;')
    after = replace_once(after, '\t/* So that subsequent socket matching not to require other lookups. */\n\tskb->sk = sk;\n', '')
    after = replace_once(after, '\t}\n}\n\nstatic const struct nla_policy nft_socket_policy',
        '\t}\n\n\t/* Lookup returns a reference; an existing skb socket is borrowed. */\n'
        '\tif (sk != skb->sk)\n\t\tsock_gen_put(sk);\n}\n\nstatic const struct nla_policy nft_socket_policy')
    expected[name] = after
    if not TARGET.exists():
        shutil.copytree(SOURCE, TARGET, symlinks=True)
    previous_file = ROOT / 'artifacts/droidspaces/extensions-network-source.json'
    previous = json.loads(previous_file.read_text()) if previous_file.exists() else {}
    records, patch = {}, []
    for name, after in expected.items():
        before = (SOURCE / name).read_text()
        current = (TARGET / name).read_text()
        known_prior = previous.get('modified_sources', {}).get(name, {})
        from_prior_revision = (known_prior.get('before_sha256') == hashlib.sha256(before.encode()).hexdigest() and
                               known_prior.get('after_sha256') == hashlib.sha256(current.encode()).hexdigest())
        if current not in (before, after) and not from_prior_revision:
            raise RuntimeError('Unrelated edits in isolated source: ' + name)
        if current != after:
            (TARGET / name).write_text(after)
        records[name] = {'before_sha256': hashlib.sha256(before.encode()).hexdigest(),
                         'after_sha256': hashlib.sha256(after.encode()).hexdigest()}
        patch.extend(difflib.unified_diff(before.splitlines(True), after.splitlines(True),
                                         fromfile='a/' + name, tofile='b/' + name))
    target = ROOT / 'patches/nft-socket-4.14-compat.patch'
    patch_text = ''.join(patch)
    if not target.exists() or target.read_text() != patch_text:
        target.write_text(patch_text)
    record = {'accepted_source_preserved': str(SOURCE), 'candidate_source': str(TARGET),
              'modified_sources': records, 'patch_sha256': hashlib.sha256(target.read_bytes()).hexdigest(),
              'rationale': '4.14 afi and bounded register parser API, self-contained includes; NFT_BREAK without a socket; '
                           'namespace check and lookup ref release consistent with xt_socket in this baseline'}
    record_file = ROOT / 'artifacts/droidspaces/extensions-network-source.json'
    record_text = json.dumps(record, indent=2) + '\n'
    if not record_file.exists() or record_file.read_text() != record_text:
        record_file.write_text(record_text)
    print(json.dumps(record, indent=2))


if __name__ == '__main__':
    main()
