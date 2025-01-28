import requests
import sqlite3
import logging
import configparser
from datetime import datetime
import time
from pathlib import Path
from web3 import Web3
import pandas as pd


# Configuration Manager
class Config:
    def __init__(self, config_file='./config.ini'):
        self.config = configparser.ConfigParser()
        if not Path(config_file).exists():
            self._create_default_config()
        self.config.read(config_file)

        if not self.config.has_section('SECURITY'):
            self.config.add_section('SECURITY')
            self.config.set('SECURITY', 'GOPLUS_API_KEY', 'your_goplus_key')
            self.config.set('SECURITY', 'MAX_TOP_HOLDERS_PCT', '40')
            self.config.set('SECURITY', 'MIN_LP_LOCK_DAYS', '30')
            self.config.set('SECURITY', 'BUNDLED_SUPPLY_THRESHOLD', '25')

    def _create_default_config(self):
        self.config['API'] = {
            'API_KEY': 'YOUR_API_KEY',
            'API_URL': 'https://pro-api.coinmarketcap.com/v1/cryptocurrency/market-pairs/latest'
        }
        self.config['DATABASE'] = {
            'NAME': 'crypto_arbitrage.db',
            'PRUNE_DAYS': '30'
        }
        self.config['FILTERS'] = {
            'MIN_VOLUME_24H': '1000000',
            'ALLOWED_EXCHANGES': 'binance,coinbase,kraken,bitfinex',
            'MAX_SPREAD_PCT': '1.5'
        }
        self.config['BLACKLIST'] = {
            'EXCHANGES': 'unknown_exchange,test_exchange',
            'PAIRS': 'ETH-TEST'
        }
        self.config['SETTINGS'] = {
            'FETCH_INTERVAL': '300',
            'CRYPTO_IDS': '1,1027',
            'TREND_ANALYSIS_HOURS': '6'
        }
        with open('config.ini', 'w') as f:
            self.config.write(f)

    @property
    def api_key(self):
        return self.config['API']['API_KEY']

    @property
    def blacklisted_exchanges(self):
        return [x.strip().lower() for x in
                self.config['BLACKLIST']['EXCHANGES'].split(',')]

    @property
    def allowed_exchanges(self):
        return [x.strip().lower() for x in
                self.config['FILTERS']['ALLOWED_EXCHANGES'].split(',')]

    def get_filters(self):
        return {
            'min_volume': float(self.config['FILTERS']['MIN_VOLUME_24H']),
            'max_spread': float(self.config['FILTERS']['MAX_SPREAD_PCT'])
        }

    def get_settings(self):
        return {
            'fetch_interval': int(self.config['SETTINGS']['FETCH_INTERVAL']),
            'crypto_ids': [int(x) for x in self.config['SETTINGS']['CRYPTO_IDS'].split(',')],
            'trend_hours': int(self.config['SETTINGS']['TREND_ANALYSIS_HOURS'])
        }


class ContractScanner:
    def __init__(self, config):
        self.config = config.config
        self.w3 = Web3(Web3.HTTPProvider(self.config.get('API', 'INFURA_URL')))
        self.goplus_url = "https://api.gopluslabs.io/api/v1/token_security/"

    def is_contract_safe(self, token_address):
        """Check contract safety using GoPlus Security API"""
        params = {
            'contract_addresses': token_address,
            'chain_id': 1  # Ethereum mainnet
        }
        try:
            response = requests.get(
                self.goplus_url,
                params=params,
                timeout=10
            )
            data = response.json()
            if data['code'] != 1:
                return False
            result = data['result'][token_address.lower()]
            return self._parse_security_data(result)
        except Exception as e:
            logging.exception(f"Security API error: {str(e)}")
            return False

    def _parse_security_data(self, security_data):
        """Evaluate multiple security factors"""
        checks = {
            'is_open_source': security_data.get('is_open_source') == '1',
            'is_proxy': security_data.get('is_proxy') == '0',
            'is_mintable': security_data.get('is_mintable') == '0',
            'is_whitelisted': security_data.get('is_whitelisted') == '1',
            'is_anti_whale': security_data.get('is_anti_whale') == '1',
            'trading_cooldown': security_data.get('trading_cooldown') == '1',
            'honeypot_score': int(security_data.get('honeypot_within_100', '100')) < 20
        }
        return all(checks.values())


class SupplyAnalyzer:
    def __init__(self, config):
        self.config = config
        self.etherscan_url = "https://api.etherscan.io/api"

    def has_bundled_supply(self, token_address):
        """Check if top holders control too much supply"""
        params = {
            'module': 'token',
            'action': 'tokenholderlist',
            'contractaddress': token_address,
            'apikey': self.config.get('API', 'ETHERSCAN_KEY'),
            'page': 1,
            'offset': 10
        }

        try:
            response = requests.get(self.etherscan_url, params=params)
            data = response.json()

            if data['status'] != '1':
                return False

            total_supply = self._get_total_supply(token_address)
            top_holders = sum(
                int(holder['value']) for holder in data['result'][:5]
            ) / 10 ** 18  # Assuming 18 decimals

            return (top_holders / total_supply * 100) > float(
                self.config.get('SECURITY', 'BUNDLED_SUPPLY_THRESHOLD')
            )

        except Exception as e:
            logging.exception(f"Supply analysis failed: {str(e)}")
            return False


# Enhanced Database Manager with Pruning
class DatabaseManager:
    def __init__(self, db_name):
        self.conn = sqlite3.connect(db_name)
        self._create_tables()

    def _create_tables(self):
        cursor = self.conn.cursor()
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS prices (
                id INTEGER PRIMARY KEY,
                crypto_id INTEGER,
                exchange TEXT,
                price REAL,
                volume_24h REAL,
                timestamp DATETIME
            )
        ''')
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS token_blacklist (
                address TEXT PRIMARY KEY,
                reason TEXT,
                timestamp DATETIME
            )
        ''')
        self.conn.commit()

    def prune_old_data(self, days=30):
        cursor = self.conn.cursor()
        cursor.execute('''
            DELETE FROM prices 
            WHERE timestamp < datetime('now', ?)
        ''', (f'-{days} days',))
        self.conn.commit()

    def insert_price_data(self, crypto_id, exchange, price, volume):
        cursor = self.conn.cursor()
        cursor.execute('''
            INSERT INTO prices (crypto_id, exchange, price, volume_24h, timestamp)
            VALUES (?, ?, ?, ?, ?)
        ''', (crypto_id, exchange, price, volume, datetime.now()))
        self.conn.commit()

    def get_filtered_prices(self, crypto_id, min_volume):
        cursor = self.conn.cursor()
        cursor.execute('''
            SELECT exchange, price FROM prices
            WHERE crypto_id = ? 
            AND volume_24h >= ?
            ORDER BY timestamp DESC
            LIMIT 100
        ''', (crypto_id, min_volume))
        return cursor.fetchall()

    def add_to_blacklist(self, token_address, reason):
        cursor = self.conn.cursor()
        cursor.execute('''
            INSERT OR REPLACE INTO token_blacklist 
            VALUES (?, ?, ?)
        ''', (token_address.lower(), reason, datetime.now()))
        self.conn.commit()

    def is_blacklisted(self, token_address):
        cursor = self.conn.cursor()
        cursor.execute('''
            SELECT 1 FROM token_blacklist 
            WHERE address = ?
        ''', (token_address.lower(),))
        return cursor.fetchone() is not None

    def close(self):
        return self.conn.close()

# Enhanced Data Fetcher with Filters
class DataFetcher:
    def __init__(self, config, db, scanner, analyzer):
        self.config = config
        self.session = requests.Session()
        self.headers = {
            'Accept': '*/*',
            'X-CMC_PRO_API_KEY': self.config.api_key
        }
        self.db = db
        self.scanner = scanner
        self.analyzer = analyzer
        self.cmc_url = "https://pro-api.coinmarketcap.com/v1/cryptocurrency/listings/latest"

    def fetch_market_pairs(self, crypto_id):
        try:
            params = {'id': crypto_id, 'limit': 200, 'sort_dir': 'desc', 'start': 1}
            response = self.session.get(
                self.config.config['API']['API_URL'],
                headers=self.headers,
                params=params
            )
            response.raise_for_status()
            return self._filter_market_data(response.json())
        except Exception as e:
            logging.exception(f"API Error: {str(e)}")
            return None

    def _filter_market_data(self, data):
        filtered_pairs = []
        blacklist = self.config.blacklisted_exchanges
        allowed = self.config.allowed_exchanges
        for pair in data.get('data', {}).get('market_pairs', []):
            exchange = pair.get('exchange', {}).get('name', '').lower()
            quote = pair.get('quote', {}).get('USD', {})
            if (exchange not in blacklist and
                    exchange in allowed and
                    quote.get('volume_24h', 0) >= self.config.get_filters()['min_volume']):
                filtered_pairs.append({
                    'exchange': exchange,
                    'price': quote.get('price'),
                    'volume': quote.get('volume_24h')
                })
        return filtered_pairs

    def fetch_and_validate_tokens(self):
        params = {
            'start': 1,
            'limit': 100,
            'convert': 'USD'
        }
        headers = {
            'X-CMC_PRO_API_KEY': self.config.get('API', 'API_KEY')
        }
        try:
            response = requests.get(
                self.cmc_url,
                headers=headers,
                params=params
            )
            tokens = response.json()['data']
            valid_tokens = []
            for token in tokens:
                if self._validate_token(token):
                    valid_tokens.append(token)
            return valid_tokens
        except Exception as e:
            logging.exception(f"CMC fetch error: {str(e)}")
            return []

    def _validate_token(self, token):
        address = token['platform']['token_address']
        if self.db.is_blacklisted(address):
            return False
        if not self.scanner.is_contract_safe(address):
            self.db.add_to_blacklist(address, "Unsafe contract")
            return False
        if self.analyzer.has_bundled_supply(address):
            self.db.add_to_blacklist(address, "Bundled supply")
            return False
        return True


# Enhanced Arbitrage Analyzer with Spread Filter
class ArbitrageAnalyzer:
    def __init__(self, config):
        self.max_spread = config.get_filters()['max_spread']

    def detect_arbitrage_opportunities(self, prices):
        if not prices:
            return []
        df = pd.DataFrame(prices, columns=['exchange', 'price'])
        df['price'] = pd.to_numeric(df['price'])
        min_price = df['price'].min()
        max_price = df['price'].max()
        spread = ((max_price - min_price) / min_price) * 100
        opportunities = []
        if spread > self.max_spread:
            opportunities.append({
                'min_exchange': df.loc[df['price'].idxmin()]['exchange'],
                'max_exchange': df.loc[df['price'].idxmax()]['exchange'],
                'spread': round(spread, 2),
                'min_price': round(min_price, 2),
                'max_price': round(max_price, 2)
            })
        return opportunities


# Main Application with Enhanced Features
class CryptoArbitrageTracker:
    def __init__(self):
        logging.basicConfig(level=logging.INFO)
        self.config = Config()
        self.db = DatabaseManager(self.config.config['DATABASE']['NAME'])
        self.scanner = ContractScanner(self.config)
        self.analyzer = SupplyAnalyzer(self.config)
        self.fetcher = DataFetcher(self.config, self.db, self.scanner, self.analyzer)
        self.arbitrage_analyzer = ArbitrageAnalyzer(self.config)
        self.settings = self.config.get_settings()
        # self.notifier = TelegramNotifier(self.config)

    def run(self):
        try:
            while True:
                # Data collection with filters
                for crypto_id in self.settings['crypto_ids']:
                    filtered_data = self.fetcher.fetch_market_pairs(crypto_id)
                    if filtered_data:
                        self._process_market_data(crypto_id, filtered_data)
                # Arbitrage detection with volume filter
                self._check_arbitrage_opportunities()
                # Periodic maintenance
                if datetime.now().hour % 6 == 0:
                    self.db.prune_old_data(int(self.config.config['DATABASE']['PRUNE_DAYS']))
                    logging.info("Database maintenance completed")
                time.sleep(self.settings['fetch_interval'])
        except KeyboardInterrupt:
            logging.info("Shutting down...")
            self.db.close()
    def _process_market_data(self, crypto_id, filtered_data):
        for pair in filtered_data:
            self.db.insert_price_data(
                crypto_id,
                pair['exchange'],
                pair['price'],
                pair['volume']
            )

    def _check_arbitrage_opportunities(self):
        filters = self.config.get_filters()
        for crypto_id in self.settings['crypto_ids']:
            prices = self.db.get_filtered_prices(crypto_id, filters['min_volume'])
            opportunities = self.arbitrage_analyzer.detect_arbitrage_opportunities(prices)
            if opportunities:
                for opp in opportunities:
                    message = (
                        f"🚨 <b>Arbitrage Opportunity</b> 🚨\n"
                        f"Coin ID: {crypto_id}\n"
                        f"Buy: {opp['min_exchange']} @ ${opp['min_price']}\n"
                        f"Sell: {opp['max_exchange']} @ ${opp['max_price']}\n"
                        f"Spread: {opp['spread']}%\n"
                        f"Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}"
                    )
                    logging.info(message)
                    # self.notifier.send_message(message)  # Send Telegram notification

class TelegramNotifier:
    def __init__(self, config):
        self.bot_token = config.get('TELEGRAM', 'BOT_TOKEN')
        self.chat_id = config.get('TELEGRAM', 'CHAT_ID')
        self.base_url = f"https://api.telegram.org/bot{self.bot_token}"

    def send_message(self, text):
        try:
            url = f"{self.base_url}/sendMessage"
            payload = {
                'chat_id': self.chat_id,
                'text': text,
                'parse_mode': 'HTML'
            }
            response = requests.post(url, data=payload)
            response.raise_for_status()
        except Exception as e:
            logging.exception(f"Telegram send failed: {str(e)}")

if __name__ == "__main__":
    tracker = CryptoArbitrageTracker()
    tracker.run()
    config = Config()
    db = DatabaseManager(config.config.get('DATABASE', 'NAME'))
    scanner = ContractScanner(config)
    analyzer = SupplyAnalyzer(config)
    fetcher = DataFetcher(config, db, scanner, analyzer)
    while True:
        valid_tokens = fetcher.fetch_and_validate_tokens()
        logging.info(f"Found {len(valid_tokens)} safe tokens")
        # Procss valid tokens for arbitrage...
        t = int(config.get('SETTINGS', 'SCAN_INTERVAL'))
        logging.info(f"Next iteration in {t} seconds")
        time.sleep(t)
