# Definition Tests

Definition System V1 fixture coverage lives under `tests/fixtures/definition`.

Use:

```powershell
npm run defs:generate
npm run defs:validate
npm run defs:coverage
```

The validation command covers:

1. committed API definition JSON files
2. committed definition metadata JSON files
3. positive definition fixtures
4. negative definition fixtures
5. negative ID metadata fixtures
6. Rohitab XML importer fixture output
7. coverage status bucket checks
