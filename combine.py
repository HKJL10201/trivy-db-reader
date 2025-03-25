import csv

IN1 = 'outputDebian.csv'
IN2 = 'outputSeverity.csv'


def loadCSV(fn):
    with open(fn) as fp:
        reader = csv.reader(fp)
        return [row for row in reader]


def dedupDedian(text: list):
    res = []
    for row in text[1:]:
        cve, code, pkg, ver = row
        if code == '2':
            res.append([cve, pkg, ver])
    return res


def initSeverity(fn):
    res = {}
    text = loadCSV(fn)
    for row in text[1:]:
        cve, code, sev = row
        if sev:
            sev = sev.split()[-1]
        res[cve] = sev
    return res


def main():
    debian = loadCSV(IN1)
    debian = dedupDedian(debian)
    severity = initSeverity(IN2)
    res = [['CVE', 'Severity', 'Package', 'Version']]
    for row in debian:
        cve, pkg, ver = row
        sev = severity[cve]
        res.append([cve, sev, pkg, ver])
    with open('output.csv', 'w', newline='') as wt:
        writer = csv.writer(wt)
        writer.writerows(res)


main()
