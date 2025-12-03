
# Khaata Credit Management - Server Setup

This application allows you to run a local credit management server accessible to other PCs on the same network. Follow these steps to set it up.

---

## **1. Place the App Folder**

* Copy the entire application folder to the **server computer** (main PC that will host the server).

---

## **2. Find Your Server IP**

1. Open **PowerShell** or **Command Prompt**.

2. Run the command:

   ```powershell
   ipconfig
   ```

3. Locate your **IPv4 Address** under the active network adapter (e.g., `192.168.1.100`).

---

## **3. Configure the Server**

1. Open `config.json` in a text editor.

2. Replace the `"host"` value with your **server IPv4 address**:

   ```json
   {
     "host": "192.168.1.100",
     "port": 8080,
     "log_level": "info",
     "access_log": true
   }
   ```

3. Save the file.

> ⚠ **Tip:** Keep `"port"`, `"log_level"`, and `"access_log"` as desired.

---

## **4. Allow Python Through Firewall**

1. Open **Windows Defender Firewall**.

2. Click **Allow an app through firewall**.

3. Click **Allow another app…**.

4. Browse to your **Python executable** (e.g., `python.exe` in your Conda environment).

5. Enable **both**:

   * ✔ Private
   * ✔ Public

6. Click **Add** and then **OK**.

---

## **5. Run the Server**
* Double click on server app. The server will start this will run the app
## Alternatively

* Open **PowerShell** in the app folder.
* Run the server using:

```powershell
python server.py
```

> The server will start and create a `server.log` file automatically in the app folder.

* Access the dashboard on any computer in your local network via:

```
http://<SERVER_IP>:8080/dashboard
```

---

## **6. Optional:**


* Place the `config.json` alongside the `.exe`. The app will read it automatically.

---

## **7. Logs**

* All server logs, including requests and errors, are saved in `server.log`.

---

## **Support**

* Make sure all client PCs are on the same network as the server.
* Firewall must allow access to the server port (`8080` by default).