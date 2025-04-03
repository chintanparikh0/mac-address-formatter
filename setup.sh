#!/bin/bash

# Make directories
mkdir -p ~/.streamlit/
mkdir -p exports/
mkdir -p logs/

# Create Streamlit config
echo "[theme]
primaryColor='#FF4B4B'
backgroundColor='#FFFFFF'
secondaryBackgroundColor='#F0F2F6'
textColor='#262730'
font='sans serif'

[server]
headless = true
enableCORS = false
enableXsrfProtection = true

[browser]
gatherUsageStats = false

[logger]
level = 'info'" > ~/.streamlit/config.toml 