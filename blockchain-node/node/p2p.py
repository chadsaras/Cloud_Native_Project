"""Peer-to-peer gossip over HTTP.

Real clients speak devp2p/RLPx over TCP with an encrypted handshake and a
Kademlia DHT for discovery. This uses plain HTTP POST to a static peer list,
which is the single largest simplification in the node.

It is the right simplification for this project: the events an operator
monitors -- peers joining and leaving, churn, blocks and attestations arriving
from a given peer, invalid blocks attributed to a peer -- have the same shape
regardless of the transport underneath. What is lost is anything that depends
on the discovery protocol itself, which is noted in the limitations section of
the README.
"""

import json
import threading
import urllib.error
import urllib.request
from collections import deque

from . import events


class PeerManager:
    """Tracks peers and gossips messages to them.

    Churn is measured over a sliding window because the interesting signal is
    the rate of peer table changes, not the count. A node with eight stable
    peers and a node cycling through eight peers a second both report eight
    peers; only one of them is being eclipsed.
    """

    CHURN_WINDOW_SEC = 30
    CHURN_THRESHOLD = 12

    def __init__(self, node_id: str, self_url: str):
        self.node_id = node_id
        self.self_url = self_url
        self.peers: dict = {}            # peer id -> base url
        self.churn_events = deque()
        self.lock = threading.Lock()

    def add_peer(self, peer_id: str, url: str, source_ip: str = "0.0.0.0") -> bool:
        if peer_id == self.node_id:
            return False
        with self.lock:
            if peer_id in self.peers:
                return False
            self.peers[peer_id] = url
            count = len(self.peers)
            self._record_churn()
        events.peer_connected(peer_id, source_ip, count)
        self._check_churn(count)
        return True

    def remove_peer(self, peer_id: str, reason: str = "disconnected") -> None:
        with self.lock:
            if peer_id not in self.peers:
                return
            del self.peers[peer_id]
            count = len(self.peers)
            self._record_churn()
        events.peer_disconnected(peer_id, reason, count)
        self._check_churn(count)

    def _record_churn(self) -> None:
        import time
        now = time.time()
        self.churn_events.append(now)
        while self.churn_events and now - self.churn_events[0] > self.CHURN_WINDOW_SEC:
            self.churn_events.popleft()

    def _check_churn(self, peer_count: int) -> None:
        if len(self.churn_events) >= self.CHURN_THRESHOLD:
            events.peer_churn(peer_count, len(self.churn_events))
            self.churn_events.clear()   # avoid alerting every event thereafter

    def broadcast(self, path: str, payload: dict) -> None:
        """Fire-and-forget gossip to every peer.

        Threaded and non-blocking: a peer that has gone away must not stall
        block production. A real client has proper backpressure and scoring;
        here a failing peer is simply dropped after one failure, which is
        aggressive but keeps the peer table honest during a demo.
        """
        with self.lock:
            targets = list(self.peers.items())

        for peer_id, url in targets:
            threading.Thread(
                target=self._send, args=(peer_id, url, path, payload), daemon=True
            ).start()

    def _send(self, peer_id: str, url: str, path: str, payload: dict) -> None:
        body = json.dumps({"from": self.node_id, "from_url": self.self_url,
                           "payload": payload}).encode()
        req = urllib.request.Request(
            f"{url}{path}", data=body, method="POST",
            headers={"Content-Type": "application/json"},
        )
        try:
            urllib.request.urlopen(req, timeout=3).read()
        except (urllib.error.URLError, TimeoutError, OSError):
            self.remove_peer(peer_id, reason="unreachable")
