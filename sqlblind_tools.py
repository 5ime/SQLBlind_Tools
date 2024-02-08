import re
import argparse
import subprocess
from urllib.parse import unquote

def print_banner():
    print("""  _________      .__ __________.__  .__            .___  ___________           .__          
 /   _____/ _____|  |\______   \  | |__| ____    __| _/  \__    ___/___   ____ |  |   ______
 \_____  \ / ____/  | |    |  _/  | |  |/    \  / __ |     |    | /  _ \ /  _ \|  |  /  ___/
 /        < <_|  |  |_|    |   \  |_|  |   |  \/ /_/ |     |    |(  <_> |  <_> )  |__\___ \ 
/_______  /\__   |____/______  /____/__|___|  /\____ |_____|____| \____/ \____/|____/____  >
        \/    |__|           \/             \/      \/_____/                             \/  
                                                                            author: iami233
                                                                            version: 1.0.0""")

def parse_arguments():
    parser = argparse.ArgumentParser(description="从PCAP文件中提取和处理数据.")
    parser.add_argument('-f', '--file', help='PCAP文件路径', required=True)
    parser.add_argument('-r', '--regexp', help='使用指定正则表达式提取数据')
    parser.add_argument('-o', '--output', help='将所有URI输出到指定文件中')
    return parser.parse_args()

def extract_uris(pcapng, output_file=None):
    cmd = ['tshark', '-r', pcapng, '-Y', 'http.request.full_uri']
    try:
        result = subprocess.run(cmd, text=True, check=True, capture_output=True, encoding='utf-8')
        data = [unquote(unquote(line.strip())) for line in result.stdout.splitlines() if line.strip()]

        if output_file and data:
            with open(output_file, 'w') as file:
                for match in data:
                    file.write(match + '\n')

        return data
    except subprocess.CalledProcessError as e:
        print(f"\033[91mError executing tshark: {e}\033[0m")
        return []

def extract_data(uri, custom_regex=None):
    is_ascii = 'ascii(' in uri
    is_compare = '<' in uri or '>' in uri
    matches = re.findall(get_regex(is_ascii, is_compare, custom_regex), uri)

    if matches:
        if is_compare:
            return [(match[0], match[-1]) for match in matches] if matches else None
        elif is_ascii and not is_compare:
            return int(matches[-1])
        else:
            return [(match[0], match[-1]) for match in matches]

    return None

def translate_data(data):
    flag = ''
    try:
        for i, num in enumerate(data[:-1]):
            if num > data[i+1]:
                flag += chr(num)
        if data and data[-1] > data[-2]:
            flag += chr(data[-1])
    except Exception as e:
        flag = ''.join(str(item) for item in data)
    return flag

def highlight_flag(flag):
    pattern = r'(?:flag|ctf|dasctf)(\[[^\]]+\]|\{[^\}]+\})'
    highlight = re.sub(pattern, lambda m: '\033[91m' + m.group(0) + '\033[0m', flag)
    return highlight

global_regex = None
def get_regex(is_ascii, is_compare, custom_regex = None):
    global global_regex

    if custom_regex:
        global_regex = custom_regex
    elif is_ascii and not is_compare:
        global_regex = r"[=<>][\"']?([0-9]{2,3})[\"']?"
    elif is_compare:
        global_regex = r"\), ?(\d+),.+[<>=][\"']?([0-9]{2,3})[\"']?"
    else:
        global_regex = r"(\d+),1(.*)?=[\"']?([a-fA-F\d]+)[\"']?"

    return global_regex

def process_data(unique_data, global_regex):
    print("\033[35m[*] 正则表达式:\033[0m", global_regex)
    print("\033[33m[*] 处理数据...\033[0m")
    [print(re.sub(global_regex, lambda m: '\033[91m' + m.group(0) + '\033[0m', path)) for path in unique_data]
    
def extract_and_process_data(uris, custom_regex=None):
    data = []
    for uri in uris:
        matches = re.findall('(?:GET|POST)\s+(.*)\s+HTTP', uri)[0]

        half = matches[:int(len(matches) / 2)]
        if half not in [x[:int(len(x) / 2)] for x in data]:
            data.append(matches)

    extracted_data = []
    for uri in uris:
        extracted = extract_data(uri, custom_regex)
        if extracted:
            extracted_data.append(extracted)
    return data, extracted_data

def handle_extracted_data(extracted_data):
    flag = ''
    if isinstance(extracted_data[0], list):
        extracted_data = [item for sublist in extracted_data for item in sublist]
        result_dict = {i[0]: i[1] for i in extracted_data}
        for key, value in result_dict.items():
            try:
                if 32 < int(value) < 127:
                    flag += chr(int(value))
                else:
                    flag = ''.join(result_dict.values())
            except Exception:
                pass
    else:
        flag = translate_data(extracted_data)

    if flag:
        print("\033[32m[+] 提取到的数据:\033[0m")
        print(highlight_flag(flag))
    else:
        print("\033[91m[!] 匹配成功，但内容为空，请检查正则是否正确.\033[0m")

def main():
    print_banner()
    args = parse_arguments()
    
    print("\033[96m[-] URI 数据取样...\033[0m")
    uris = extract_uris(args.file, args.output)

    unique_uris, extracted_data = extract_and_process_data(uris, args.regexp)

    [print(path) for path in unique_uris]
    
    process_data(unique_uris, global_regex)
    
    if extracted_data:
        handle_extracted_data(extracted_data)
    else:
        print("\033[91m[!] 未找到数据.\033[0m")

if __name__ == "__main__":
    main()