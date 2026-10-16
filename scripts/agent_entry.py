"""Frozen native agent/service and administrative lifecycle entry point."""
import multiprocessing
import sys


def main():
    multiprocessing.freeze_support()
    if len(sys.argv) > 1:
        command, args = sys.argv[1], sys.argv[2:]
        if command == 'service-dispatch':
            from agent.service import dispatch
            if len(args) != 1:
                raise SystemExit('Expected service-dispatch worker|gateway')
            dispatch(args[0])
            return 0
        if command == 'service-register':
            from pathlib import Path
            from agent.service import register_services
            register_services(Path(sys.executable))
            return 0
        if command == 'verify-installation':
            from agent.service import verify_installation
            verify_installation()
            return 0
        if command == 'migrate':
            from agent.migration import main as migrate
            return migrate(args)
        if command in ('install', 'repair', 'remove', 'update', 'rollback', 'client-startup', 'client'):
            from agent.management import main as manage
            return manage([command] + args)
    from agent.__main__ import main as agent_main
    return agent_main()


if __name__ == '__main__':
    raise SystemExit(main())
