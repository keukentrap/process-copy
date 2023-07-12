from keystone import *
import fileinput
import sys

CODE = ""
NR = sys.argv[1] if len(sys.argv) > 1 else 1
ASM = f"shellcode{NR}.asm"
CPP = f"DummyProgram{NR}.cpp"


try:
    ks = Ks(KS_ARCH_X86, KS_MODE_64)
    print(f"Running Keystone on: {ASM}")
    with open(ASM, 'r', encoding="utf-8") as f:
        CODE = f.read()
    encoding, count = ks.asm(CODE)
    string = ""
    for i in encoding:
        string += f"\\x{i:x}"
    print(f"Putting result in: {CPP}")
    justsawpayload = False
    for line in fileinput.input(CPP, inplace=True):
        if line.startswith("const char payload[] ="):
            print(f"const char payload[] = \"{string}\";")
            print(f"/* x86-64bit ASM \n{CODE}\n*/")
            justsawpayload = True
        elif justsawpayload:
            if line == "*/\n":
                justsawpayload = False
            if line.startswith("int main("):
                justsawpayload = False
                print("\n" + line, end='')
            # skip printing this line
        else:
            print(line, end='')
        
except KsError as e:
    print("ERROR: %s" %e)