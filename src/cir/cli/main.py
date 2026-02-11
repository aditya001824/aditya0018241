"""Command-line interface for the Cyber Incident Response system."""
import sys
import argparse


def main():
    """Main CLI entry point."""
    parser = argparse.ArgumentParser(
        description='Cyber Incident Response System - CLI'
    )
    
    subparsers = parser.add_subparsers(dest='command', help='Available commands')
    
    # Server command
    server_parser = subparsers.add_parser('server', help='Start the API server')
    server_parser.add_argument('--host', default='0.0.0.0', help='Host')
    server_parser.add_argument('--port', type=int, default=8000, help='Port')
    
    # Demo command
    subparsers.add_parser('demo', help='Run the demo')
    
    args = parser.parse_args()
    
    if args.command == 'server':
        print(f"Starting server on {args.host}:{args.port}")
        import uvicorn
        uvicorn.run("cir.api.server:app", host=args.host, port=args.port)
    elif args.command == 'demo':
        print("Running demo...")
        import subprocess
        import os
        demo_path = os.path.join(os.path.dirname(__file__), '..', '..', '..', 'examples', 'demo.py')
        subprocess.run([sys.executable, demo_path])
    else:
        parser.print_help()


if __name__ == "__main__":
    main()
