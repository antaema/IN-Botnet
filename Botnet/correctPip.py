from pip import main
if __name__ == '__main__':
    sys.exit(main())
to this:

from pip import __main__
if __name__ == '__main__':
    sys.exit(__main__._main())
