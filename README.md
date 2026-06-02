# Alap elemzés (csak statisztika):
python3 apache_analyzer.py --file valami.log

# Biztonsági vizsgálat:
python3 apache_analyzer.py --file valami.log --scan --database patterns.db

# Biztonsági vizsgálat 5-ös burst küszöbbel:
python3 apache_analyzer.py --file valami.log --scan --database patterns.db --threshold 5

# Tesztek futtatása:
python3 tests.py
