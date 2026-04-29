import sys
from core.analyzer import analyze, compare
from reports.generator import render_full_report, render_comparison, export_pdf

def main():
    args = sys.argv[1:]

    if not args:
        print("Usage:")
        print("  python vendor_risk_radar.py <vendor>")
        print("  python vendor_risk_radar.py --compare <vendor1> <vendor2>")
        print("  python vendor_risk_radar.py --export <vendor>")
        sys.exit(1)

    if args[0] == "--compare" and len(args) == 3:
        result = compare(args[1], args[2])
        render_comparison(result)
    elif args[0] == "--export" and len(args) == 2:
        result = analyze(args[1])
        render_full_report(result)
        path = export_pdf(result)
        print(f"\nPDF exported: {path}")
    elif len(args) == 1:
        result = analyze(args[0])
        render_full_report(result)
    else:
        print("Invalid arguments.")
        sys.exit(1)

if __name__ == "__main__":
    main()