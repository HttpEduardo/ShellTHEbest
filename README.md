<h1 align="center">
  ShellCaçador
</h1>

<p align="center">
  É uma ferramenta simples para testar a vulnerabilidade do shell
<br/><br/>
  
<img alt="Python 3.8" src="https://img.shields.io/badge/python-3.8-yellow.svg">
<img alt="Supported_OS Linux orange" src="https://img.shields.io/badge/Supported_OS-Linux-orange.svg">
<img alt="Supported OS Mac" src="https://img.shields.io/badge/Supported_OS-Mac-orange.svg">
</p>

```
### Shellhunter (softw bug)

hellhunter, também conhecido como Bashdoor, é uma família de bugs de segurança no shell Unix Bash, sendo o primeiro deles divulgado em 24 de setembro de 2014. hellhunter pode permitir que um invasor faça com que o Bash execute comandos arbitrários e obtenha acesso não autorizado a muitos serviços voltados para a Internet, como servidores web, que usam Bash para processar solicitações.


### Installation
> Use the package manager [pip](https://pip.pypa.io/en/stable/)

### Pip

```
pip install shodan
pip install ipinfo
```

### Help

```
python main.py --help

                        

                     _             _             
                    | |_| | | | | '_ \| __/ _ \ '__|                
                    | |  |  _  | |_| | | | | ||  __/ |                 
                    | |  |_| |_|\__,_|_| |_|\__\___|_|                     
                                                
                   
   By: VOID                                                                         

```       
Argumentos opcionais:	Descrição:
-h, --help	Mostra esta mensagem de ajuda e sai
–file <ips.txt>	Insira a lista de hosts de destino
–range	Define o intervalo de IP, ex.: 192.168.15.1,192.168.15.100
–cmd-cgi	Define o comando shell que será executado na carga útil
–exec-vuln	Executa comandos em alvos vulneráveis
–thread <20>, -t <20>	Define o número de threads, ex.: 20
–check	Verifica a vulnerabilidade do shellshock
–ssl	Habilita solicitação com SSL
–cgi-file <cgi.txt>	Define um arquivo CGI a ser usado
–timeout <5>	Define o tempo limite de conexão
–all	Testa todas as cargas úteis
–debug, -d	Habilita o modo de depuração

```

### Tree

```bash
├── assets
│   ├── autor.json
│   ├── config.json
│   ├── exploits.json
│   └── prints
│       ├── banner.png
│       ├── print00.png
│       ├── print01.png
│       ├── print02.png
│       └── print03.png
├── LICENSE
├── main.py
├── modules
│   ├── banner_shock.py
│   ├── color_shock.py
│   ├── debug_shock.py
│   ├── file_shock.py
│   ├── __init__.py
│   ├── request_shock.py
│   ├── shodan_shock.py
│   └── thread_shock.py
├── output
│   └── vuln.txt
├── README.md
└── wordlist
    └── cgi.txt
```

### Ref
- https://en.wikipedia.org/wiki/Shellhunter_%28software_bug%29#CVE-2014-7186_and_CVE-2014-7187_Details
- https://blog.inurl.com.br/search?q=shellshock
- https://github.com/opsxcq/exploit-CVE-2014-6271
- https://en.wikipedia.org/wiki/Shellhunter_%28software_bug%29#CVE-2014-7186_and_CVE-2014-7187_Details
- https://manualdousuario.net/shellshock-bash-falha/
- https://darrenmartyn.ie/2021/01/24/visualdoor-sonicwall-ssl-vpn-exploit


### Roadmap
Eu comecei este projeto para estudar um pouco mais de Python e interagir mais com APIs como o Shodan e o Ipinfo.
* [x] Command line structure
* [x] Banner
* [x] File management class
* [x] HttpRequests management class
* [x] Shell Exec on vulnerable targets
* [x] Process debug

@VOID# ShellTHEbest
