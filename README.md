# Make all scripts executable
chmod +x awjunaid-main.sh
chmod +x lib/*.sh
chmod +x modules/*.sh

# Run the scan
bash awjunaid-main.sh -d rayepenber.tech -m soft

# Verbose mode
bash awjunaid-main.sh -d example.com -m medium -v

# Hard scan
bash awjunaid-main.sh -d example.com -m hard -t 20
