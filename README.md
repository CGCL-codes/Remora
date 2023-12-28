### Description
This project is used to implement asynchronous BFT. 

There are two variants of ForkBFT, names “fork0”, “fork1” .
"fork0" is a basic version, which is similar to Ditto's fallback path and only fixes some problems of it.
"fork1" is our asynchronous protocol.

There are two DAG BFT, names "qcdag", "tusk".
"qcdag" is our DAG protocol --QCDAG.
"tusk" is the DAG protocol in the paper: [Eurosys'22]Narwhal and Tusk: a DAG-based mempool and efficient BFT consensus

### Steps to run BFT
Commands below are run on the *work computer*.

#### 1. Install go (1.14+)
```
sudo apt-get update
mkdir tmp
cd tmp
wget https://dl.google.com/go/go1.16.15.linux-amd64.tar.gz
sudo tar -xvf go1.16.15.linux-amd64.tar.gz
sudo mv go /usr/local
```

#### 2. Install pip3 and ansible
```
sudo apt install python3-pip
sudo pip3 install --upgrade pip
pip3 install ansible
```

#### 3. Configure the environment
```
echo 'export PATH=$PATH:~/.local/bin:/usr/local/go/bin' >> ~/.bashrc
source ~/.bashrc
go env -w GO111MODULE="on"  
go env -w GOPROXY=https://goproxy.io
```

#### 4. Login without passwords
Enable *work computer* to login in servers without passwords.
