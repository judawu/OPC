import logging
import os
import glob
import datetime
import shutil
import asyncio

import re
        
def set_logging_level(level:int=0):
    """Set the logging level for the application."""
    
    levels = {
        0: logging.DEBUG,
        1: logging.INFO,
        2: logging.WARNING,
        3: logging.ERROR,
        4: logging.CRITICAL
    }
    newlevel=levels.get(level,logging.INFO)
    logging.getLogger().setLevel(newlevel)
    

    
def rename_existing_log(log_file: str):
    """Rename existing log file with date suffix if it exists."""
    if os.path.exists(log_file):
        date_suffix = datetime.datetime.now().strftime("%Y%m%d")
        base, ext = os.path.splitext(log_file)
        new_name = f"{base}_{date_suffix}{ext}"
        counter = 1
        while os.path.exists(new_name):
            new_name = f"{base}_{date_suffix}_{counter}{ext}"
            counter += 1
        shutil.move(log_file, new_name)
        logging.info(f"_OPCUALogger_.rename_existing_log:Renamed existing log file to {new_name}")

async def rotate_daily_logs(log_file: str):
        """Move non-current day's logs to date-specific files."""
        # Regular expression to validate date format (YYYY-MM-DD)
        date_pattern = re.compile(r'^\d{4}-\d{2}-\d{2}$')
        
        while True:
            try:
                current_date = datetime.datetime.now().strftime("%Y-%m-%d")
                base_dir = os.path.dirname(log_file)
                temp_file = log_file + ".temp"
                
                # Read current log file and separate today's vs older logs
                today_logs = []
                old_logs = {}
                
                if os.path.exists(log_file):
                    with open(log_file, 'r') as f:
                        for line in f:
                            try:
                                # Extract date from log line (format: 2025-04-26 14:30:45,123)
                                log_date = line[:10]
                                # Validate date format
                                if date_pattern.match(log_date):
                                    if log_date == current_date:
                                        today_logs.append(line)
                                    else:
                                        if log_date not in old_logs:
                                            old_logs[log_date] = []
                                        old_logs[log_date].append(line)
                                else:
                                    # Keep invalid lines in today's log to avoid loss
                                    today_logs.append(line)
                            except Exception as e:
                                logging.warning(f"Skipping malformed log line: {line.strip()} - {str(e)}")
                                today_logs.append(line)  # Keep malformed lines in current log

                    # Write today's logs back to main log file
                    with open(temp_file, 'w') as f:
                        f.writelines(today_logs)

                    # Write older logs to date-specific files
                    for log_date, lines in old_logs.items():
                        # Double-check date format before creating file
                        if date_pattern.match(log_date):
                            date_file = os.path.join(base_dir, f"opcuuaserver_{log_date.replace('-', '')}.log")
                            with open(date_file, 'a') as f:
                                f.writelines(lines)
                        else:
                            logging.warning(f"Skipping invalid date format: {log_date}")

                    # Replace original log file with today's logs
                    if os.path.exists(temp_file):
                        shutil.move(temp_file, log_file)

            except Exception as e:
                logging.error(f"Error in daily log rotation: {str(e)}")
            
            # Wait until next day
            tomorrow = datetime.datetime.now().replace(hour=0, minute=0, second=0, microsecond=0) + datetime.timedelta(days=1)
            await asyncio.sleep((tomorrow - datetime.datetime.now()).total_seconds())

async def cleanup_old_logs(period: str, log_dir: str):
    """Periodically clean up old log files based on specified period."""
    periods = {
        'week': 7,
        'month': 30,
        'year': 365
    }
    
    if period.lower() not in periods:
        logging.error(f"Invalid cleanup period: {period}")
        return
    
    days = periods[period.lower()]

    while True:
        try:
            current_time = datetime.datetime.now()
            for log_file in glob.glob(os.path.join(log_dir, "opcuuaserver_*.log")):
                try:
                    # Extract date from filename (opcuuaserver_YYYYMMDD.log)
                    date_str = os.path.basename(log_file)[12:20]
                    file_date = datetime.datetime.strptime(date_str, "%Y%m%d")
                    age = (current_time - file_date).days
                    if age > days:
                        os.remove(log_file)
                        logging.info(f"Deleted old log file: {log_file}")
                except:
                    continue
        except Exception as e:
            logging.error(f"Error in log cleanup: {str(e)}")
                # Wait for next cleanup (once a day)
        await asyncio.sleep(86400)
            
       