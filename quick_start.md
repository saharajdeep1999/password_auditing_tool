# Single password analysis
python auditor.py "YourP@ssw0rd!" --breach-check

# Analyze hashed passwords (auto-detects type)
python auditor.py 5baa61e4c9b93f3f0682250b6cf8331b7ee68fd8

# Bulk audit from file
python auditor.py -f passwords.txt -o report.csv
