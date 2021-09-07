#   Copyright 2021 Marcus LaFerrera
#
#   Licensed under the Apache License, Version 2.0 (the "License");
#   you may not use this file except in compliance with the License.
#   You may obtain a copy of the License at
#
#       http://www.apache.org/licenses/LICENSE-2.0
#
#   Unless required by applicable law or agreed to in writing, software
#   distributed under the License is distributed on an "AS IS" BASIS,
#   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#   See the License for the specific language governing permissions and
#   limitations under the License.

from argparse import ArgumentParser
from datetime import datetime, timedelta
import json
import random
import string

from faker import Factory
from pydantic import BaseModel

from flatten_json import flatten

fake = Factory.create()

__author__ = "Marcus LaFerrera <@mlaferrera>"
__version__ = "0.1.0"


def to_dot_notation(data, **kwargs) -> str:
    return json.dumps(flatten(data, separator="."), **kwargs)


def random_uid() -> str:
    return "".join(random.choices(string.ascii_letters + string.digits, k=17))


class ZeekModel(BaseModel):
    ts: datetime = datetime.now()
    uid: str = random_uid()

    class Config:
        json_dumps = to_dot_notation
        json_encoders = {datetime: lambda v: f"{v.isoformat()}Z"}

    def update_ts(self, min_jitter: int = 60, max_jitter: int = 28_800) -> None:
        jitter = random.uniform(min_jitter, max_jitter)
        self.ts = self.ts + timedelta(seconds=jitter)

    def update_uid(self) -> None:
        self.uid = random_uid()


class conn(BaseModel):
    orig_h: str = fake.ipv4_private()
    orig_p: int = fake.port_number(is_dynamic=True)
    resp_h: str = fake.ipv4_public()
    resp_p: int = 443

    def new_client_port(self) -> None:
        self.orig_p = fake.port_number(is_dynamic=True)


class ssl(ZeekModel):
    id: conn = conn()
    version: str = "TLSv12"
    cipher: str = "TLS_AES_128_GCM_SHA256"
    curve: str = "x25519"
    server_name: str = fake.hostname()
    resumed: bool = True
    established: bool = True
    ja3: str = fake.md5()
    ja3s: str = fake.md5()

    def new(self) -> None:
        self.id.new_client_port()
        self.update_ts()
        self.update_uid()


if __name__ == "__main__":
    parser = ArgumentParser()
    parser.add_argument(
        "-c", "--count", type=int, default=10, help="Number of sessions to generate"
    )
    parser.add_argument(
        "-r",
        "--random",
        action="store_true",
        default=False,
        help="Generate random sessions",
    )

    args = parser.parse_args()

    # Malicious domains associated with SUNBURST
    malicious_domains = [
        "avsvmcloud.com",
        "digitalcollege.org",
        "freescanonline.com",
        "deftsecurity.com",
        "thedoccloud.com",
        "websitetheme.com",
        "highdatabase.com",
        "incomeupdate.com",
        "databasegalore.com",
        "panhardware.com",
        "zupertech.com",
        "seobundlekit.com",
        "lcomputers.com",
        "virtualdataserver.com",
        "webcodez.com",
        "infinitysoftwares.com",
        "ervsystem.com",
    ]

    # Malicious IPs associated with SUNBURST
    malicious_ips = [
        "13.59.205.66",
        "54.193.127.66",
        "54.215.192.52",
        "34.203.203.23",
        "139.99.115.204",
        "5.252.177.25",
        "5.252.177.21",
        "204.188.205.176",
        "51.89.125.18",
        "167.114.213.199",
    ]

    # Create malicious session with Solarwinds C2's
    if args.random:
        # Create malicious session with completely random hosts
        malicious_session = ssl()
    else:
        malicious_session = ssl(
            server_name=random.choice(malicious_domains),
            id=conn(resp_h=random.choice(malicious_ips)),
        )

    for _ in range(args.count):
        print(malicious_session.json())
        malicious_session.new()
