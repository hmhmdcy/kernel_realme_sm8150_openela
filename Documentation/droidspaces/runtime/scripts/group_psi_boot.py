"""Exact v1 boot-header exception for the group-PSI enablement candidate."""
STAGE = 'android16-group-psi'
RECLAIM_STAGE = 'android16-group-psi-reclaim-fix'
STAGES = frozenset((STAGE, RECLAIM_STAGE))
DISABLE = 'cgroup_disable=pressure'


def remove_pressure_disable(cmdline):
    # The reviewed ROM header has exactly one final disable argument. Preserve
    # every other byte; combined or differently positioned arguments need review.
    if cmdline.split().count(DISABLE) != 1 or not cmdline.endswith(' ' + DISABLE):
        raise RuntimeError('Unexpected original pressure-disable argument')
    return cmdline[:-len(' ' + DISABLE)]


def header_cmdline(header):
    if len(header) != 1648 or header[:8] != b'ANDROID!' or header[40:44] != b'\x01\x00\x00\x00':
        raise RuntimeError('PSI exception requires the reviewed v1 boot header')
    return (header[64:576].split(b'\0', 1)[0] + header[608:1632].split(b'\0', 1)[0]).decode('ascii')


def validate_header_change(original, candidate):
    old = bytearray(original[:1648])
    new = bytearray(candidate[:1648])
    original_cmdline = header_cmdline(old)
    wanted = remove_pressure_disable(original_cmdline)
    if header_cmdline(new) != wanted:
        raise RuntimeError('PSI candidate changed additional boot arguments')
    encoded = wanted.encode('ascii')
    # Layout comes from the pinned AOSP mkbootimg write_header: 512-byte
    # cmdline, 32-byte SHA identifier, then 1024-byte extra_cmdline.
    old[64:576] = encoded[:512].ljust(512, b'\0')
    old[608:1632] = encoded[512:].ljust(1024, b'\0')
    for start, end in ((8, 12), (576, 608)):
        old[start:end] = b'\0' * (end - start)
        new[start:end] = b'\0' * (end - start)
    if old != new:
        raise RuntimeError('PSI candidate changed other non-kernel header fields')
    return {'action': 'remove one final cgroup_disable=pressure argument',
        'before': original_cmdline, 'after': wanted, 'validated': True}
