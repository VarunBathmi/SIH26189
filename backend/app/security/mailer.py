import os
import smtplib
from pathlib import Path
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from typing import Optional, Dict, Any
from dotenv import load_dotenv

# Load root .env if not already loaded
root_env = Path(__file__).resolve().parent.parent.parent.parent / ".env"
if root_env.exists():
    load_dotenv(dotenv_path=root_env)
else:
    load_dotenv()

def get_smtp_config() -> Dict[str, Any]:
    host = os.getenv("SMTP_HOST")
    port = os.getenv("SMTP_PORT")
    user = os.getenv("SMTP_USER")
    pass_ = os.getenv("SMTP_PASS")
    from_ = os.getenv("SMTP_FROM")

    vars_dict = {
        "SMTP_HOST": host,
        "SMTP_PORT": port,
        "SMTP_USER": user,
        "SMTP_PASS": pass_,
        "SMTP_FROM": from_
    }
    defined_count = sum(1 for v in vars_dict.values() if v is not None and v != "")

    is_configured = defined_count == 5
    port_int = int(port) if port and port.isdigit() else 587
    clean_pass = pass_.replace(" ", "") if pass_ else ""
    return {
        "is_configured": is_configured,
        "host": host,
        "port": port_int,
        "user": user,
        "pass": clean_pass,
        "from": from_
    }

def send_otp_email(to: str, otp: str, expiry_minutes: int = 10) -> Dict[str, Any]:
    if not to or not isinstance(to, str):
        raise ValueError("Recipient email is required.")

    clean_to = to.strip().lower()
    subject = "SIH Investigation Portal - Your Login Verification Code"
    text_body = (
        f"Your single-use verification code for the SIH Criminal Investigation Network Platform is: {otp}\n\n"
        f"This code expires in {expiry_minutes} minutes.\n\n"
        f"If you did not attempt this action, notify your system administrator immediately."
    )
    html_body = f"""
    <div style="font-family: Arial, sans-serif; max-width: 500px; margin: 0 auto; padding: 20px; border: 1px solid #e0e0e0; border-radius: 8px;">
      <h2 style="color: #1a365d; margin-top: 0;">SIH Investigation Platform</h2>
      <p style="color: #4a5568; font-size: 14px;">Use the verification code below to complete your authentication.</p>
      <div style="background-color: #edf2f7; padding: 15px; border-radius: 6px; text-align: center; margin: 20px 0;">
        <span style="font-size: 28px; font-weight: bold; letter-spacing: 6px; color: #2b6cb0;">{otp}</span>
      </div>
      <p style="color: #718096; font-size: 12px;">This one-time passcode will expire in <strong>{expiry_minutes} minutes</strong>.</p>
      <hr style="border: 0; border-top: 1px solid #e2e8f0; margin: 20px 0;" />
      <p style="color: #a0aec0; font-size: 11px;">If you did not request this code, please ignore this email or contact the forensic admin team immediately.</p>
    </div>
    """

    config = get_smtp_config()

    if not config["is_configured"]:
        print(f"\n[DEV MAIL] OTP for {clean_to}: {otp} (valid for {expiry_minutes}m)\n")
        return {"delivered": False, "dev_mode": True, "preview": otp}

    try:
        msg = MIMEMultipart("alternative")
        msg["Subject"] = subject
        msg["From"] = config["from"]
        msg["To"] = clean_to

        part1 = MIMEText(text_body, "plain")
        part2 = MIMEText(html_body, "html")
        msg.attach(part1)
        msg.attach(part2)

        if config["port"] == 465:
            with smtplib.SMTP_SSL(config["host"], config["port"], timeout=10) as server:
                server.login(config["user"], config["pass"])
                server.sendmail(config["from"], [clean_to], msg.as_string())
        else:
            with smtplib.SMTP(config["host"], config["port"], timeout=10) as server:
                server.starttls()
                server.login(config["user"], config["pass"])
                server.sendmail(config["from"], [clean_to], msg.as_string())

        return {"delivered": True, "recipient": clean_to}
    except Exception as e:
        print(f"[SMTP ERROR] Failed to send email to {clean_to}: {e}")
        return {"delivered": False, "error": str(e), "dev_mode": True, "preview": otp}
