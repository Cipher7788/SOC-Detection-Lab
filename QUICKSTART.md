# QUICKSTART Guide for SOC Detection Lab

## Introduction
Welcome to the SOC Detection Lab! This guide will help you get the lab running in just 5 minutes.

## Prerequisites
- A valid GitHub account.
- Docker installed on your machine.
- Basic understanding of command line operations.

## Step 1: Clone the Repository
Open your terminal and run the following command:
```bash
git clone https://github.com/Cipher7788/SOC-Detection-Lab.git
```

## Step 2: Install Dependencies
Navigate to the cloned directory and run:
```bash
cd SOC-Detection-Lab
```  
```bash
docker-compose up -d
```

## Step 3: Configure the Environment
Make sure to set any necessary environment variables required by the lab:
```bash
echo "export LAB_ENV=production" >> ~/.bashrc
source ~/.bashrc
```

## Step 4: Start the Lab
To start the lab, use:
```bash
docker-compose up
```

## Step 5: Access the Lab
Once the lab is running, you can access it via your browser at:
```
http://localhost:8080
```

## Conclusion
You are now ready to explore the SOC Detection Lab! For more detailed instructions, refer to the full documentation.