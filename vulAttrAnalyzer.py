import json

IN = 'vulnerability.txt'
OUT = 'vulAttr.txt'

testdata = '''{"Title":"SQL Injection in sequelize",
"Description":"sequelize is an Object-relational mapping, or a middleman to convert things from Postgres, MySQL, MariaDB, SQLite and Microsoft SQL Server into usable data for NodeJS In Postgres, SQLite, and Microsoft SQL Server there is an issue where arrays are treated as strings and improperly escaped. This causes potential SQL injection in sequelize 3.19.3 and earlier, where a malicious user could put `[\"test\", \"'); DELETE TestTable WHERE Id = 1 --')\"]` inside of ``` database.query('SELECT * FROM TestTable WHERE Name IN (:names)', { replacements: { names: directCopyOfUserInput } }); ``` and cause the SQL statement to become `SELECT Id FROM Table WHERE Name IN ('test', '\\'); DELETE TestTable WHERE Id = 1 --')`. In Postgres, MSSQL, and SQLite, the backslash has no special meaning. This causes the the statement to delete whichever Id has a value of 1 in the TestTable table.",
"Severity":"HIGH",
"CweIDs":["CWE-89"],
"VendorSeverity":{"ghsa":3,"nvd":3},
"CVSS":{"ghsa":{"V3Vector":"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H","V3Score":7.5},"nvd":{"V2Vector":"AV:N/AC:L/Au:N/C:N/I:N/A:P","V3Vector":"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H","V2Score":5,"V3Score":7.5}},
"References":["https://github.com/sequelize/sequelize/commit/23952a2b020cc3571f090e67dae7feb084e1be71","https://github.com/sequelize/sequelize/commits/v3.20.0?after=62e4dacb28a779a190a3e042b971dcd8c7926e49+34\u0026branch=v3.20.0\u0026qualified_name=refs%2Ftags%2Fv3.20.0","https://github.com/sequelize/sequelize/issues/5671","https://nodesecurity.io/advisories/102","https://nvd.nist.gov/vuln/detail/CVE-2016-10556"],"PublishedDate":"2018-05-29T20:29:00.75Z","LastModifiedDate":"2019-10-09T23:16:46.403Z"}
'''


def load(fn):
    with open(fn, encoding='utf-8') as f:
        return f.read().splitlines()


def main():
    text = load(IN)
    res = set()
    for idx, line in enumerate(text):
        print(f'\r{idx}', end='')
        js = '{' + line.split(': {')[1]
        try:
            jsd = json.loads(js)
        except:
            continue
        keys = set(jsd.keys())
        res = res.union(keys)
    res = sorted(list(res))
    with open(OUT, 'w') as wt:
        wt.write('\n'.join(res))
    print('\ndone')


main()


def test():
    teststr = r'[\"test\", \">>>>>"here"'
    print(teststr)
    print(teststr.replace(r'\"', "'"))
    json.loads(testdata.replace(r'\"', "'"))


# test()

'''
Title*
Description*
Severity*
VendorSeverity
CVSS
CweIDs
PublishedDate
LastModifiedDate
References
'''
