# ddns-tools
==========


## Helper tools for Dynamic DNS APIs

## Setting up systemd Service

- Copy the service script into the systemd directory
```bash
cat dnsmadeeasy-ddns.service | sudo tee /etc/systemd/system/dnsmadeeasy-ddns.service
```

- Reload systemd
```bash
sudo systemctl daemon-reload
```

- Enable and activate the DDNS service
```bash
sudo systemctl enable dnsmadeeasy-ddns.service
sudo systemctl start dnsmadeeasy-ddns.service
```

- Verify
```bash
sudo systemctl status dnsmadeeasy-ddns.service
sudo journalctl -u dnsmadeeasy-ddns.service -f
```