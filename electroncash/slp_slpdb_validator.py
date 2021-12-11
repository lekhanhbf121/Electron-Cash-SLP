import json
import requests
import base64
import threading

from electroncash.slp_graph_search import slp_gs_mgr
from .util import PrintError


class SLPDBValidationJob(PrintError):
    def __init__(self, txid, number_of_validations_needed, callback):
        self.txid = txid
        self.number_of_validations_needed = number_of_validations_needed
        self.callback = callback
        self.validity = 0
        self.query = {
            "v": 3,
            "q": {
                "db": ["c", "u"],
                "aggregate": [
                    {
                        "$match": {
                            "tx.h": self.txid
                        }
                    },
                    {
                        "$limit": 1
                    },
                    {
                        "$project": {
                            "tx.h": "$tx.h",
                            "slp.valid": "$slp.valid",
                            "slp.invalidReason": "$slp.invalidReason"
                        }
                    }
                ],
                "limit": 1
            }
        }

    def _query_server(self, server):
        try:
            query_to_string = json.dumps(self.query)
            query_b64 = base64.b64encode(query_to_string.encode("utf-8"))
            b64_to_str = str(query_b64)
            query_path = b64_to_str[2:-1]
            url = server + query_path

            result = requests.get(url=url, timeout=30)
            result_json = result.json()
        except Exception as e:
            self.print_error(e)
            raise (Exception("Server was not reachable or something went wrong."))

        if result_json["c"]:  # confirmed tx
            tx_data = result_json["c"]
        if result_json["u"]:  # unconfirmed tx
            tx_data = result_json["u"]
        return tx_data

    def validate(self):
        slpdb_servers = slp_gs_mgr.slpdb_host
        valid_counter = 0
        for server in slpdb_servers:
            try:
                result = self._query_server(server)
                if result:
                    self.print_error(server, result[0]["slp"]["valid"])
                    if result[0]["slp"]["valid"]:
                        valid_counter += 1
                        if valid_counter >= self.number_of_validations_needed:
                            break
            except Exception as e:
                self.print_exception(e)
                continue

        if valid_counter >= self.number_of_validations_needed:
            self.validity = 1
        else:
            self.validity = 2
        self.callback(self)


class SLPDBValidationJobManager(PrintError):
    def __init__(self, thread_name="SLPDBValidation"):
        self.jobs_list = list()

        self.run_validation = threading.Event()
        self.thread = threading.Thread(target=self.mainloop, name=thread_name, daemon=True)
        self.thread.start()

    def _pause_mainloop(self):
        self.run_validation.clear()

    def _resume_mainloop(self):
        self.run_validation.set()

    def add_job(self, slpdb_validation_job):
        self.jobs_list.append(slpdb_validation_job)
        self._resume_mainloop()

    def mainloop(self):
        while True:
            self.run_validation.wait()
            if self.jobs_list:
                job = self.jobs_list.pop()
                job.validate()
            else:
                self._pause_mainloop()
