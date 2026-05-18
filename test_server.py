import asyncio
import importlib.util
import pathlib
import sys

SERVER_PATH = pathlib.Path('/home/ubuntu/projects/chuansuan-selector/server.py')
VENV_SITE = SERVER_PATH.parent / 'venv' / 'lib' / 'python3.11' / 'site-packages'
if str(VENV_SITE) not in sys.path:
    sys.path.insert(0, str(VENV_SITE))
spec = importlib.util.spec_from_file_location('server_under_test', SERVER_PATH)
server = importlib.util.module_from_spec(spec)
spec.loader.exec_module(server)


def test_run_strategies_requires_minimum_candles():
    result = server.run_strategies([{'c': 1, 'h': 1, 'l': 1}] * 10)
    assert 'error' in result
    assert result['strategies'] == {}


def test_resample_candles_groups_and_preserves_ohlc():
    candles = [
        {'t': 1, 'o': 10, 'h': 12, 'l': 9, 'c': 11, 'v': 100},
        {'t': 2, 'o': 11, 'h': 13, 'l': 10, 'c': 12, 'v': 120},
        {'t': 3, 'o': 12, 'h': 14, 'l': 11, 'c': 13, 'v': 80},
        {'t': 4, 'o': 13, 'h': 15, 'l': 12, 'c': 14, 'v': 90},
    ]
    grouped = server.resample_candles(candles, 2)
    assert grouped == [
        {'t': 1, 'o': 10, 'h': 13, 'l': 9, 'c': 12, 'v': 220},
        {'t': 3, 'o': 12, 'h': 15, 'l': 11, 'c': 14, 'v': 170},
    ]


def test_timeframe_maps_expand_history_and_keep_15m_distinct():
    assert server.STOCK_TIMEFRAMES['15m']['interval'] == '15m'
    assert server.STOCK_TIMEFRAMES['month']['period'] in {'10y', 'max'}
    assert server.STOCK_TIMEFRAMES['year']['interval'] in {'3mo', '1mo'}
    assert server.CRYPTO_TIMEFRAMES['15m'][0] == 1
    assert server.CRYPTO_TIMEFRAMES['year'][0] >= 1825


def test_market_indices_use_real_index_symbols():
    assert server.MARKET_INDEX_SYMBOLS['SPX']['symbol'] == '^GSPC'
    assert server.MARKET_INDEX_SYMBOLS['NDX']['symbol'] == '^IXIC'
    assert server.MARKET_INDEX_SYMBOLS['DJI']['symbol'] == '^DJI'


def test_gold_symbol_uses_xau_not_gld():
    assert server.GOLD_SYMBOL == 'GC=F'
    assert server.GOLD_DISPLAY_SYMBOL == 'XAU/USD'


def test_enrich_watchlist_items_computes_portfolio_metrics():
    async def fake_stock_info(symbol):
        return {'price': 110, 'change': 5, 'name': symbol}

    async def fake_crypto_price(symbol):
        return {'price': 55, 'change_24h': 10}

    async def fake_stock_chart(symbol, period='1mo', interval='1d'):
        if period == '5d':
            return [
                {'t': 1, 'o': 100, 'h': 101, 'l': 99, 'c': 100},
                {'t': 2, 'o': 100, 'h': 103, 'l': 99, 'c': 110},
            ]
        return [
            {'t': 1, 'o': 80, 'h': 81, 'l': 79, 'c': 80},
            {'t': 2, 'o': 80, 'h': 111, 'l': 79, 'c': 110},
        ]

    async def fake_crypto_chart(symbol, timeframe='month'):
        if timeframe == 'week':
            return [
                {'t': 1, 'o': 50, 'h': 51, 'l': 49, 'c': 50},
                {'t': 2, 'o': 50, 'h': 56, 'l': 49, 'c': 55},
            ]
        return [
            {'t': 1, 'o': 40, 'h': 41, 'l': 39, 'c': 40},
            {'t': 2, 'o': 40, 'h': 56, 'l': 39, 'c': 55},
        ]

    server.yf_info = fake_stock_info
    server.api_cp = fake_crypto_price
    server.yf_chart = fake_stock_chart
    server.get_crypto_chart_by_timeframe = fake_crypto_chart

    items = [
        {'symbol': 'AAPL', 'type': 'stock', 'cost_basis': 100.0, 'quantity': 2.0, 'notes': 'core'},
        {'symbol': 'BTC', 'type': 'crypto', 'cost_basis': 40.0, 'quantity': 0.5, 'notes': ''},
    ]

    enriched = asyncio.run(server.enrich_watchlist_items(items))
    assert enriched[0]['current_price'] == 110
    assert enriched[0]['position_value'] == 220
    assert enriched[0]['profit_amount'] == 20
    assert enriched[0]['week_change_pct'] == 10.0
    assert enriched[0]['month_change_pct'] == 37.5
    assert enriched[1]['current_price'] == 55
    assert enriched[1]['position_value'] == 27.5
    assert enriched[1]['profit_pct'] == 37.5
