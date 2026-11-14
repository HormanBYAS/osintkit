"""Módulos de criptomonedas y actividad on-chain."""

from __future__ import annotations

from typing import Any

from ..core import Context, Finding, module
from ..http import HttpError, NetworkError
from ..util import crypto_network
from .base import f, safe_json


def _btc(ctx: Context, address: str) -> list[Finding]:
    findings: list[Finding] = []
    data = safe_json(ctx, f"https://blockstream.info/api/address/{address}", timeout=25)
    if isinstance(data, dict):
        chain = data.get("chain_stats") or {}
        mempool = data.get("mempool_stats") or {}
        funded = int(chain.get("funded_txo_sum", 0)) + int(mempool.get("funded_txo_sum", 0))
        spent = int(chain.get("spent_txo_sum", 0)) + int(mempool.get("spent_txo_sum", 0))
        balance = funded - spent
        tx_count = int(chain.get("tx_count", 0)) + int(mempool.get("tx_count", 0))
        findings += [
            f("Red", "Bitcoin", "info"),
            f("Saldo", f"{balance / 100_000_000:.8f} BTC", "info"),
            f("Recibido", f"{funded / 100_000_000:.8f} BTC", "info"),
            f("Enviado", f"{spent / 100_000_000:.8f} BTC", "info"),
            f("Transacciones", str(tx_count), "info"),
            f("Explorador", f"https://mempool.space/address/{address}", "link",
              url=f"https://mempool.space/address/{address}"),
        ]
        txs = safe_json(ctx, f"https://blockstream.info/api/address/{address}/txs", timeout=25)
        if isinstance(txs, list) and txs:
            times = []
            for tx in txs:
                status = tx.get("status") or {}
                if status.get("block_time"):
                    times.append(int(status["block_time"]))
            if times:
                import datetime

                first = datetime.datetime.fromtimestamp(min(times), datetime.timezone.utc).isoformat()
                last = datetime.datetime.fromtimestamp(max(times), datetime.timezone.utc).isoformat()
                findings.append(f("Primera actividad (muestra)", first, "info"))
                findings.append(f("Última actividad (muestra)", last, "info"))
        return findings
    # Respaldo blockchain.info
    data = safe_json(ctx, f"https://blockchain.info/rawaddr/{address}?limit=20", timeout=25)
    if isinstance(data, dict):
        return [
            f("Red", "Bitcoin", "info"),
            f("Saldo", f"{int(data.get('final_balance', 0)) / 100_000_000:.8f} BTC", "info"),
            f("Recibido", f"{int(data.get('total_received', 0)) / 100_000_000:.8f} BTC", "info"),
            f("Enviado", f"{int(data.get('total_sent', 0)) / 100_000_000:.8f} BTC", "info"),
            f("Transacciones", str(data.get("n_tx", 0)), "info"),
            f("Explorador", f"https://mempool.space/address/{address}", "link",
              url=f"https://mempool.space/address/{address}"),
        ]
    return [f("Bitcoin", "no se pudo consultar la dirección", "warn",
              url=f"https://mempool.space/address/{address}")]


def _eth(ctx: Context, address: str) -> list[Finding]:
    data = safe_json(ctx, f"https://eth.blockscout.com/api/v2/addresses/{address}", timeout=30)
    if not isinstance(data, dict):
        return [f("Ethereum", "no se pudo consultar la cuenta", "warn",
                  url=f"https://etherscan.io/address/{address}")]
    findings: list[Finding] = [
        f("Red", "Ethereum", "info"),
        f("Dirección", str(data.get("hash", address)), "info"),
        f("Saldo", f"{int(data.get('coin_balance', 0) or 0) / 10**18:.6f} ETH", "info"),
        f("Transacciones", str(data.get("transactions_count", 0)), "info"),
        f("Transferencias de tokens", str(data.get("token_transfers_count", 0)), "info"),
        f("Contrato", "sí" if data.get("is_contract") else "no", "warn" if data.get("is_contract") else "info"),
        f("Explorador", f"https://etherscan.io/address/{address}", "link",
          url=f"https://etherscan.io/address/{address}"),
    ]
    if data.get("ens_domain_name"):
        findings.append(f("ENS", str(data["ens_domain_name"]), "good"))
    if data.get("name"):
        findings.append(f("Etiqueta", str(data["name"]), "info"))
    if data.get("creation_transaction_hash"):
        findings.append(f("Creación", str(data["creation_transaction_hash"]), "info"))
    return findings


@module("btc_address")
def btc_address(ctx: Context, tool: Any) -> list[Finding]:
    if crypto_network(ctx.target) != "btc":
        return [f("Bitcoin", "la dirección no parece válida para Bitcoin", "warn")]
    return _btc(ctx, ctx.target)


@module("eth_address")
def eth_address(ctx: Context, tool: Any) -> list[Finding]:
    if crypto_network(ctx.target) != "eth":
        return [f("Ethereum", "la dirección no parece válida para Ethereum", "warn")]
    return _eth(ctx, ctx.target)


@module("crypto_other")
def crypto_other(ctx: Context, tool: Any) -> list[Finding]:
    address = ctx.target
    network = crypto_network(address)
    if network == "btc":
        return _btc(ctx, address)
    if network == "eth":
        return _eth(ctx, address)
    findings: list[Finding] = [f("Red detectada", network or "desconocida", "info")]
    explorers = {
        "ltc": ("Litecoin", f"https://blockchair.com/litecoin/address/{address}"),
        "doge": ("Dogecoin", f"https://blockchair.com/dogecoin/address/{address}"),
        "xmr": ("Monero", f"https://xmrchain.net/search?value={address}"),
        "trx": ("Tron", f"https://tronscan.org/#/address/{address}"),
    }
    if network in explorers:
        name, url = explorers[network]
        findings.append(f("Explorador", url, "link", url=url))
        if network == "trx":
            data = safe_json(ctx, f"https://apilist.tronscanapi.com/api/account?address={address}", timeout=25)
            if isinstance(data, dict):
                if data.get("balance") is not None:
                    findings.append(f("Saldo", f"{int(data.get('balance', 0)) / 1_000_000:.6f} TRX", "info"))
                if data.get("transactions") is not None:
                    findings.append(f("Transacciones", str(data.get("transactions")), "info"))
                if data.get("date_created"):
                    findings.append(f("Creada", str(data["date_created"]), "info"))
        elif network in ("ltc", "doge"):
            data = safe_json(ctx, f"https://api.blockchair.com/{network}/dashboards/address/{address}", timeout=25)
            if isinstance(data, dict) and isinstance(data.get("data"), dict):
                payload = list(data["data"].values())[0] if data["data"] else {}
                if isinstance(payload, dict):
                    info = payload.get("address") or {}
                    if info.get("balance") is not None:
                        divisor = 100_000_000
                        findings.append(f("Saldo", f"{int(info['balance']) / divisor:.8f} {network.upper()}", "info"))
                    if info.get("transaction_count") is not None:
                        findings.append(f("Transacciones", str(info["transaction_count"]), "info"))
    else:
        findings.append(f("Aviso", "red no reconocida o no soportada por consulta automática", "warn"))
    return findings
