#!/usr/bin/env python3
import json
import argparse
import csv
from tabulate import tabulate
from collections import Counter
from colorama import Fore, Style, init

init(autoreset=True) 

def colorize_severity(sev):
    sev_text = str(sev)
    sev_lower = sev_text.lower()
    if sev_lower == "critical":
        return Fore.RED + sev_text + Style.RESET_ALL
    elif sev_lower == "high":
        return Fore.LIGHTRED_EX + sev_text + Style.RESET_ALL
    elif sev_lower == "medium":
        return Fore.YELLOW + sev_text + Style.RESET_ALL
    elif sev_lower == "low":
        return Fore.GREEN + sev_text + Style.RESET_ALL
    elif sev_lower == "info":
        return Fore.CYAN + sev_text + Style.RESET_ALL
    return sev_text

MESSAGES = {
    "en": {
        "description": "Nuclei JSON output parser with colors (English/French)",
        "file_help": "Path to the Nuclei JSON output file",
        "severity_help": "Filter by severity (high, medium, low, critical, info)",
        "limit_help": "Maximum number of results to show",
        "sort_help": "Sort results by (severity or template)",
        "export_help": "Export results (csv)",
        "summary_title": "Findings Summary:",
        "total_findings": "Total Findings",
        "no_results": "No results match your filter.",
        "csv_saved": "CSV saved to",
        "header_names": ["template", "name", "severity", "matched-at"]
    },
    "fr": {
        "description": "Analyseur de sortie JSON Nuclei avec couleurs (Anglais/Français)",
        "file_help": "Chemin vers le fichier de sortie JSON de Nuclei",
        "severity_help": "Filtrer par sévérité (high, medium, low, critical, info)",
        "limit_help": "Nombre maximal de résultats à afficher",
        "sort_help": "Trier les résultats par (severity ou template)",
        "export_help": "Exporter les résultats (csv)",
        "summary_title": "Résumé des résultats :",
        "total_findings": "Total des résultats",
        "no_results": "Aucun résultat ne correspond à votre filtre.",
        "csv_saved": "CSV enregistré dans",
        "header_names": ["template", "name", "severity", "matched-at"]
    }
}

def load_json_file(path):
    results = []
    try:
        with open(path, "r", encoding="utf-8") as f:
            raw = f.read().strip()
            if not raw:
                return []
            try:
                data = json.loads(raw)
                if isinstance(data, dict):
                    items = [data]
                elif isinstance(data, list):
                    items = data
                else:
                    items = []
            except json.JSONDecodeError:
                items = []
                with open(path, "r", encoding="utf-8") as fh:
                    buffer = ""
                    for line in fh:
                        line = line.strip()
                        if not line:
                            continue
                        buffer += line
                        try:
                            obj = json.loads(buffer)
                            if isinstance(obj, list):
                                for element in obj:
                                    items.append(element)
                            elif isinstance(obj, dict):
                                items.append(obj)
                            buffer = ""
                        except json.JSONDecodeError:
                            buffer += "\n"
                            continue
        return items
    except FileNotFoundError:
        return []

def normalize_items(items):
    normalized = []
    for item in items:
        if isinstance(item, list) and len(item) == 1 and isinstance(item[0], dict):
            item = item[0]
        if not isinstance(item, dict):
            continue
        info = item.get("info", {}) or {}
        normalized.append({
            "template": item.get("template", "") or "",
            "name": info.get("name", "") or "",
            "severity": (info.get("severity", "") or "unknown"),
            "matched-at": item.get("matched-at", item.get("host", "")) or ""
        })
    return normalized

def main():
    pre = argparse.ArgumentParser(add_help=False)
    pre.add_argument("--lang", choices=["en","fr"], default="en")
    known, remaining = pre.parse_known_args()
    lang = known.lang
    msgs = MESSAGES[lang]

    parser = argparse.ArgumentParser(description=msgs["description"])
    parser.add_argument("file", help=msgs["file_help"])
    parser.add_argument("--severity", help=msgs["severity_help"])
    parser.add_argument("--limit", type=int, help=msgs["limit_help"])
    parser.add_argument("--sort", choices=["severity", "template"], help=msgs["sort_help"])
    parser.add_argument("--export", choices=["csv"], help=msgs["export_help"])
    parser.add_argument("--lang", choices=["en","fr"], default=lang, help="Output language (en or fr)")
    args = parser.parse_args()

    items = load_json_file(args.file)
    data = normalize_items(items)

    if not data:
        print(msgs["no_results"])
        return

    severity_counts = Counter([d.get("severity", "unknown").lower() for d in data])

    results = data
    if args.severity:
        sev_filter = args.severity.lower()
        results = [r for r in results if r.get("severity","").lower() == sev_filter]

    if args.sort == "severity":
        order = {"critical": 1, "high": 2, "medium": 3, "low": 4, "info": 5, "unknown": 6}
        results.sort(key=lambda x: order.get(x.get("severity","").lower(), 99))
    elif args.sort == "template":
        results.sort(key=lambda x: x.get("template",""))

    if args.limit:
        results = results[:args.limit]

    print("\n" + msgs["summary_title"])
    for sev in ["critical", "high", "medium", "low", "info", "unknown"]:
        if sev in severity_counts:
            label = sev.capitalize()
            print(f"  {label:<10}: {severity_counts[sev]}")
    print(f"  {msgs['total_findings']} : {len(data)}\n")

    if results:
        table = []
        for r in results:
            table.append({
                "template": r.get("template",""),
                "name": r.get("name",""),
                "severity": colorize_severity(r.get("severity","")),
                "matched-at": r.get("matched-at","")
            })
        print(tabulate(table, headers="keys", tablefmt="grid"))
    else:
        print(msgs["no_results"])

    if args.export == "csv":
        csv_file = "nuclei_results.csv"
        with open(csv_file, "w", newline="", encoding="utf-8") as f:
            writer = csv.DictWriter(f, fieldnames=msgs["header_names"])
            writer.writeheader()
            for r in results:
                writer.writerow({
                    "template": r.get("template",""),
                    "name": r.get("name",""),
                    "severity": r.get("severity",""),
                    "matched-at": r.get("matched-at","")
                })
        print(f"\n{msgs['csv_saved']} {csv_file}")

if __name__ == "__main__":
    main()
