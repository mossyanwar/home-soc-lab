"""Unit tests for the event loaders and normalisers (soclab.events)."""

from soclab.events import (
    _decode_proctitle,
    _parse_auditd_line,
    _parse_sysmon_xml,
    normalise_auditd,
    normalise_sysmon_xml,
)


def test_proctitle_hex_is_decoded_with_nul_as_space():
    # "useradd\0malware_user"
    hexval = "75736572616464006d616c776172655f75736572"
    assert _decode_proctitle(hexval) == "useradd malware_user"


def test_proctitle_already_decoded_is_left_alone():
    assert _decode_proctitle("/sbin/useradd -d /home/x") == "/sbin/useradd -d /home/x"


def test_auditd_execve_fields_and_quote_stripping():
    line = 'type=EXECVE msg=audit(1604996384.965:93777): argc=4 a0="dd" a1="if=/dev/zero" a2="bs=1" a3="count=1"'
    ev = _parse_auditd_line(line)
    assert ev["_logsource"] == "auditd"
    assert ev["type"] == "EXECVE"
    assert ev["a0"] == "dd"
    assert ev["a1"] == "if=/dev/zero"


def test_auditd_ausearch_format():
    line = "type=EXECVE msg=audit(02/20/2025 10:25:25.761:92634) : argc=3 a0=base64 a1=-d a2=enc.txt"
    ev = _parse_auditd_line(line)
    assert ev["a0"] == "base64"
    assert ev["a1"] == "-d"


def test_sysmon_xml_parses_data_fields():
    xml = (
        '<Event><System><Provider Name="Linux-Sysmon"/><EventID>1</EventID>'
        '<Computer>UBU</Computer>'
        '<TimeCreated SystemTime="2022-05-11T18:10:22.0Z"/></System>'
        '<EventData><Data Name="Image">/bin/bash</Data>'
        '<Data Name="CommandLine">bash -i</Data>'
        '<Data Name="ParentImage">/usr/bin/java</Data></EventData></Event>'
    )
    ev = _parse_sysmon_xml(xml)
    assert ev["EventID"] == 1
    assert ev["Channel"] == "Linux-Sysmon/Operational"
    assert ev["Image"] == "/bin/bash"
    assert ev["ParentImage"] == "/usr/bin/java"
    assert ev["Hostname"] == "UBU"


def test_sysmon_xml_unescapes_entities():
    xml = (
        '<Event><System><EventID>1</EventID></System><EventData>'
        '<Data Name="CommandLine">sh -c &quot;echo hi&quot; &amp;&amp; id</Data>'
        "</EventData></Event>"
    )
    ev = _parse_sysmon_xml(xml)
    assert ev["CommandLine"] == 'sh -c "echo hi" && id'


def test_sysmon_xml_tolerates_truncation():
    # A line cut off mid-CommandLine still yields the fields parsed so far.
    xml = (
        '<Event><System><EventID>1</EventID></System><EventData>'
        '<Data Name="Image">/bin/bash</Data>'
        '<Data Name="CommandLine">bash -c {echo,QQ==}|{base64'
    )
    ev = _parse_sysmon_xml(xml)
    assert ev is not None
    assert ev["Image"] == "/bin/bash"
    assert ev["CommandLine"].startswith("bash -c")


def test_normalise_round_trip_on_small_strings(tmp_path):
    p = tmp_path / "a.log"
    p.write_text(
        'type=PROCTITLE msg=audit(1.0:1): proctitle=7375646F0075736572616464\n'
        'type=EXECVE msg=audit(1.0:1): argc=2 a0="id" a1="-u"\n'
    )
    evs = normalise_auditd(str(p))
    assert len(evs) == 2
    assert evs[0]["proctitle"] == "sudo useradd"
    assert evs[1]["a0"] == "id"

    x = tmp_path / "b.log"
    x.write_text('<Event><System><EventID>11</EventID></System><EventData>'
                 '<Data Name="TargetFilename">/root/.ssh/authorized_keys</Data></EventData></Event>\n')
    evs = normalise_sysmon_xml(str(x))
    assert evs[0]["TargetFilename"] == "/root/.ssh/authorized_keys"
