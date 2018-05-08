import sys
sys.path.append("..")

import scanner

def main():
    try:
        scan = scanner.Scanner()
        # scan.findLocals()
        # scan.scanUrl('lightron.org')
        # scan.scanUrl('www.desentupidorarolabosta.com.br')
        scan.findSO("74.86.201.120")
    except KeyboardInterrupt:
        print "Exit"
        sys.exit()

if __name__ == "__main__":
    main()