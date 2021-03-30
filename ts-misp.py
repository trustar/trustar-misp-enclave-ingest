import argparse
import dateutil.parser
import os
import json
from trustar import TruStar, datetime_to_millis, get_logger
from retryWrapper import retry
from pymisp import (
    PyMISP,
    MISPEvent,
    MISPObject,
    MISPAttribute,
    MISPTag,
    NewAttributeError,
)
from mappings import mappings
from configparser import RawConfigParser
from requests import HTTPError
from requests.packages.urllib3 import disable_warnings
from requests.packages.urllib3.exceptions import InsecureRequestWarning
from datetime import datetime, timedelta
from math import ceil

logger = get_logger("TruSTAR-MISP Enclave Ingest")
enclave_count = 0
event_count = 0
object_count = 0
attribute_count = 0


def get_cl_args():
    """
    Function that manages the CLI for this script
    """
    parser = argparse.ArgumentParser(prog="TruSTAR MISP Enclave Ingest")
    parser.add_argument(
        "-k",
        "-key",
        required=False,
        type=str,
        dest="misp_key",
        help="(OPTIONAL) MISP auth key - Found under the automation section on the MISP web interface",
    )
    parser.add_argument(
        "-u",
        "-url",
        required=False,
        type=str,
        dest="misp_url",
        help="(OPTIONAL) https://<your MISP URL>/",
    )
    parser.add_argument(
        "-ev",
        "-event",
        required=False,
        type=int,
        dest="use_case",
        help="(OPTIONAL) Defaults to 1 - Map a list of IOCs to one MISP Event as Attributes outside of an object. Other options are: 2 - Well-formed TruSTAR reports map to individual MISP Objects within the same MISP event; 3 - Well-formed TruSTAR reports map to an individual MISP event",
    )
    parser.add_argument(
        "-ft",
        "-from-time",
        required=False,
        type=str,
        dest="from_time",
        help="(OPTIONAL) Default is 1 day ago. From time expressed as an ISO formatted date (YYYY-MM-DD ex. 2019-11-04)",
    )
    parser.add_argument(
        "-tt",
        "-to-time",
        required=False,
        type=str,
        dest="to_time",
        help="(OPTIONAL) Default is datetime.now(). To time expressed as an ISO formatted date (YYYY-MM-DD ex. 2019-11-04)",
    )
    parser.add_argument(
        "-e",
        "-enclave-ids",
        required=False,
        type=str,
        dest="enclaves",
        help="(OPTIONAL) Default will search all private and premium intel enclaves. TruSTAR enclave id(s) to search from separated by commas. DO NOT PASS IN A LIST/ARRAY",
    )
    parser.add_argument(
        "-ec",
        "-enclave-configs",
        required=False,
        action="store_true",
        dest="enclave_configs",
        help='(OPTIONAL) Defaults to False - Specify "-ec" if you have specified you enclave configs in enclave_configs.conf. If you specify both "-ev" and "-ec" then "-ev" will be set to None. If you specify both "-e" and "-ec" the script defaults to "-e"',
    )
    parser.add_argument(
        "-ecf",
        "-enclave-configs-file",
        required=False,
        type=str,
        dest="enclave_configs_file",
        help="(OPTIONAL) Defaults to None - Path to enclave configs file. NOTE: ENCLAVE CONFIGS FILE MUST BE SETUP EXACTLY LIKE 'enclave_configs.conf' TO WORK",
    )
    parser.add_argument(
        "-db",
        "-debug",
        required=False,
        action="store_true",
        dest="debug",
        help='(OPTIONAL) Debug - Defaults to False - When "-db" is specified the script does not generate log files',
    )
    parser.add_argument(
        "-s",
        "-ssl-verify",
        required=False,
        action="store_false",
        dest="misp_verifycert",
        help='(OPTIONAL) Defaults to True - Specify "-s" if you want to skip SSL validation, best practice is to enable SSL validation',
    )
    parser.add_argument(
        "-d",
        "-distribution",
        required=False,
        type=int,
        dest="distribution",
        help="(OPTIONAL) Defaults to MISP.default_event_distribution in MISP config. Options are: 0 - Your organization only; 1 - This community only; 2 - Connected communities; 3 - All communities; 4 - Sharing Group; 5 - Inherit",
    )
    parser.add_argument(
        "-sg",
        "-sharing-group",
        required=False,
        type=int,
        dest="sharing_group",
        help="(OPTIONAL) Defaults to None. Pass in Id parameter found under List Sharing Groups",
    )
    parser.add_argument(
        "-t",
        "-threat-level-id",
        required=False,
        type=int,
        dest="threat_level_id",
        help="(OPTIONAL) Defaults to MISP.default_event_threat_level in MISP config. Options are: 1 - High; 2 - Medium; 3 - Low; 4 - Undefined",
    )
    parser.add_argument(
        "-a",
        "-analysis",
        required=False,
        type=int,
        dest="analysis",
        help="(OPTIONAL) Defaults to 0 (initial analysis). Other options are: 1 - Ongoing; 2 - Completed",
    )
    parser.add_argument(
        "-p",
        "-publish",
        required=False,
        action="store_true",
        dest="publish",
        help="(OPTIONAL) Defaults to False. Set to True if you want each MISP event to publish after it's been added/updated",
    )
    parser.add_argument(
        "-c",
        "-checkpoint",
        required=False,
        action="store_true",
        dest="checkpoint",
        help="(OPTIONAL) Defaults to False. Set to True if the last run failed and you need to pick up from the checkpoint",
    )
    args = parser.parse_args()

    # Validating MISP Creds through command line or conf file
    if not args.misp_key or not args.misp_url:
        try:
            conf = config_from_file("trustar.conf", "trustar")
            args.misp_key = conf["misp_api_key"]
            args.misp_url = conf["misp_api_url"]
        except ValueError:
            logger.exception(
                "You must provide both your MISP API Key and MISP API URL in either the command line or trustar.conf"
            )
            raise

    # Validating enclaves via command line or enclave configs file
    if args.checkpoint:
        logger.info("Loading enclaves from checkpoint")
        args.checkpoint_file = f"{os.getcwd()}/checkpoint/ec_checkpoint.py"
        with open(args.checkpoint_file, "r") as f:
            args.enclaves = json.loads(f.read())
    elif args.enclave_configs:
        if not args.enclave_configs_file:
            args.enclaves = config_from_file("enclave_configs.conf")
        else:
            args.enclaves = config_from_file(args.enclave_configs_file)
        args.enclaves = [get_enclaves(v) for k, v in args.enclaves.items()]
        new_enclaves = []
        for i in range(len(args.enclaves)):
            for enclave in args.enclaves[i]:
                enclave = enclave.to_dict()
                enclave["use_case"] = i + 1
                new_enclaves.append(enclave)
        args.enclaves = new_enclaves
    else:
        if args.enclaves:
            args.enclaves = args.enclaves.replace(" ", "").split(",")
            args.enclaves = get_enclaves(args.enclaves)
        else:
            args.enclaves = get_enclaves()
        new_enclaves = []
        for enclave in args.enclaves:
            enclave = enclave.to_dict()
            enclave["use_case"] = args.use_case
            new_enclaves.append(enclave)
        args.enclaves = new_enclaves

    # Validate timestamps and convert to milliseconds
    if args.to_time and args.from_time:
        args.to_time = dateutil.parser.isoparse(args.to_time)
        args.from_time = dateutil.parser.isoparse(args.from_time)
    elif args.to_time and not args.from_time:
        args.to_time = dateutil.parser.isoparse(args.to_time)
        args.from_time = args.to_time - timedelta(days=1)
    elif not args.to_time and args.from_time:
        args.to_time = datetime.now()
        args.from_time = dateutil.parser.isoparse(args.from_time)
    else:
        args.to_time = datetime.now()
        args.from_time = args.to_time - timedelta(days=1)
    args.to_time = datetime_to_millis(args.to_time)
    args.from_time = datetime_to_millis(args.from_time)

    return args


def datetime_from_millis(dt):
    return datetime.fromtimestamp(dt / 1000).isoformat()


def config_from_file(config_file, config_role="DEFAULT"):
    """
    Create a configuration dictionary from a config file section.

    :param config_file: The path to the config file.
    :param config_role: The section within the file to use.
    :return: The configuration dictionary.
    """
    config_parser = RawConfigParser(default_section=config_role)
    config_parser.read(config_file)
    roles = dict(config_parser)

    # ensure that config file has indicated role
    if config_role in roles:
        config = dict(roles[config_role])
    else:
        logger.exception(KeyError(f"Could not find role {config_role}"))

    return config


def get_enclaves(enclave_ids=None):
    """
    Returns all of the enclaves that are Internal or Premium Intelligence for the given company
    """
    try:
        if enclave_ids is None:
            return [
                enclave
                for enclave in ts.get_user_enclaves()
                if enclave.type != "RESEARCH"
            ]
        else:
            return [
                enclave
                for enclave in ts.get_user_enclaves()
                if enclave.id in enclave_ids
            ]
    except HTTPError as e:
        raise e


def lists_of_indicators(indicators, num_sub_lists):
    """
    This helper function creates a list of sub-lists for API endpoints that have limitations
    Example: Get indicator summaries endpoint can process 100 indicators at a time, so if
    there are 900 indicators it will create 9 sub-lists of 100 indicators for the endpoint to iterate over
    """
    ioc_base_list = []
    for i in range(num_sub_lists):
        i = []
        ioc_base_list.append(i)
    odd = False
    if len(indicators) % 2 == 1:
        odd = True
    index = 0
    count = 0
    ioc_count = len(indicators)
    interval = ceil(ioc_count / num_sub_lists)
    for indicator in indicators:
        ioc_base_list[index].append(indicator)
        count += 1
        if count == interval and odd and index == num_sub_lists - 1:
            last_index = ioc_count - 1
            ioc_base_list[index].append(indicators[last_index])
            break
        elif count == interval:
            count = 0
            index += 1
    return ioc_base_list


@retry
def get_metadata(indicators, enclave_ids):
    """
    This function will return a flat list of indicators with metadata so that CS/technical clients will not have to program in the extra work for endpoint limitations
    :param ts: instance of TruSTAR's Python SDK
    :param list(Indicator) indicators: a list of |Indicator| objects
    :param list(str) enclave_ids: a list of enclave ids to pull indicator summaries from
    """
    try:
        if len(indicators) == 0:
            return []
        elif len(indicators) > 1000:
            num_sub_lists = ceil(len(indicators) / 1000)
            ioc_base_list = lists_of_indicators(indicators, num_sub_lists)
            ioc_meta_list = []
            for i in range(0, num_sub_lists):
                ioc_meta_list.append(
                    ts.get_indicators_metadata(
                        ioc_base_list[i], enclave_ids=enclave_ids
                    )
                )
            return [ioc for lst in ioc_meta_list for ioc in lst]
        else:
            return ts.get_indicators_metadata(indicators, enclave_ids=enclave_ids)
    except Exception as e:
        logger.exception(e)
        raise


@retry
def search_ts_reports(enclave, from_time, to_time):
    try:
        reports_search = ts.search_reports_page(
            enclave_ids=enclave["id"],
            from_time=from_time,
            to_time=to_time,
            page_size=100,
        )
        total_reports = reports_search.total_elements
        if total_reports == 0:
            return []
        elif total_reports > 10000:
            logger.info(
                f"{enclave['name']}: More than 10,000 reports found, executing multiple searches"
            )
            reports = []
            i = 0
            reports.append(reports_search.items)
            has_next = reports_search.has_next
            while has_next:
                i += 100
                logger.info(f"{enclave['name']}: Fetching reports {i - 100} to {i}")
                to_time = min([report.updated for report in reports_search.items])
                reports_search = ts.search_reports_page(
                    enclave_ids=enclave["id"],
                    from_time=from_time,
                    to_time=to_time,
                    page_size=100,
                )
                reports.append(reports_search.items)
                has_next = reports_search.has_next
            return [report for sublist in reports for report in sublist]
        else:
            logger.info(
                f"{enclave['name']}: Less than 10,000 reports found, returning initial search"
            )
            return list(
                ts.search_reports(
                    enclave_ids=enclave["id"],
                    from_time=from_time,
                    to_time=to_time,
                )
            )
    except Exception as e:
        logger.exception(e)
        raise


@retry
def search_ts_indicators(enclave, from_time, to_time):
    try:
        indicators_search = ts.search_indicators_page(
            enclave_ids=enclave["id"],
            from_time=from_time,
            to_time=to_time,
            page_size=1000,
        )
        total_indicators = indicators_search.total_elements
        if total_indicators == 0:
            return []
        elif total_indicators <= 1000:
            return get_metadata(indicators_search.items, enclave["id"])
        elif total_indicators > 10000:
            logger.info(
                f"{enclave['name']}: More than 10K indicators found, running paginated search"
            )
            indicators = []
            i = 0
            ind_search = get_metadata(indicators_search.items, enclave["id"])
            indicators.append(ind_search)
            has_next = indicators_search.has_next
            while has_next:
                i += 1000
                logger.info(f"Fetching indicators {i - 1000} to {i}")
                to_time = min([indicator.last_seen for indicator in ind_search])
                indicators_search = ts.search_indicators_page(
                    enclave_ids=enclave["id"],
                    from_time=from_time,
                    to_time=to_time,
                    page_size=1000,
                )
                ind_search = get_metadata(indicators_search.items, enclave["id"])
                indicators.append(ind_search)
                has_next = indicators_search.has_next
            return [indicator for sublist in indicators for indicator in sublist]
        else:
            logger.info(
                f"{enclave['name']}: Less than 10K indicators found, returning initial search"
            )
            indicators = list(
                ts.search_indicators(
                    enclave_ids=enclave["id"],
                    from_time=from_time,
                    to_time=to_time,
                )
            )
            return get_metadata(indicators, enclave["id"])
    except Exception as e:
        logger.exception(e)
        raise


def checkpoint(enclaves, completed_enclaves):
    completed_enclave_names = [enclave["name"] for enclave in completed_enclaves]
    final_enclaves = [
        enclave
        for enclave in enclaves
        if enclave["name"] not in completed_enclave_names
    ]
    checkpoint_file = f"{os.getcwd()}/checkpoint/ec_checkpoint.py"
    with open(checkpoint_file, "w") as f:
        json.dump(final_enclaves, f)


class TruStarMISP:
    """
    Class of functions to help TruSTAR send reports and IOCs to MISP
    """

    def __init__(
        self,
        misp,
        enclaves,
        from_time,
        to_time,
        distribution=None,
        threat_level_id=None,
        analysis=None,
        sharing_group=None,
        publish=None,
    ):
        """
        :param TruSTAR ts: Instance of TruSTAR Python SDK
        :param PyMISP misp: Instance of PyMISP
        :param int from_time: Starting time search parameter
        :param int to_time: Ending time search parameter
        :param int to_time: Ending time search parameter
        """
        self.misp = misp
        self.enclaves = enclaves
        self.completed_enclaves = []
        self.from_time = from_time
        self.to_time = to_time
        self.distribution = distribution
        self.threat_level_id = threat_level_id
        self.analysis = analysis
        self.sharing_group = sharing_group
        self.publish = publish
        self.globals_list = globals()

    def get_event_id(self, enclave_name=None):
        """
        Gets all MISP events that are tied to a TruSTAR enclave
        """
        if enclave_name is not None:
            try:
                event = self.misp.search(eventinfo=enclave_name)
                return (event[0]["Event"]["id"], event[0]["Event"]["uuid"])
            except Exception:
                return None, None
        else:
            return None, None

    def misp_event(self, enclave):
        event_id, event_uuid = self.get_event_id(enclave_name=enclave["name"].strip())
        event = MISPEvent()
        event.info = enclave["name"].strip()
        event.add_tag({"name": "trustar", "colour": "#3568D5"})
        event.add_tag(f"{enclave['name']}")
        event.distribution = self.distribution
        event.sharing_group_id = self.sharing_group
        event.threat_level_id = self.threat_level_id
        event.analysis = self.analysis
        if event_id:
            event.id = event_id
            event.uuid = event_uuid
            logger.info(f"Found existing event for {enclave['name']}")
            return event
        else:
            try:
                logger.info(f"Generating a MISP event for {event.info}")
                res = self.misp.add_event(event)
                if res["errors"]:
                    raise Exception(res["errors"][1]["message"])
            except KeyError:
                return event

    def check_old_events(self, report_title, enclave_name):
        old_events = self.misp.search(eventinfo=report_title)
        try:
            if old_events[0]:
                for old_event in old_events:
                    self.misp.delete_event(old_event)
                    logger.info(
                        f"{enclave_name}: Found prior version of {report_title}, updating"
                    )
        except IndexError:
            logger.info(f"{enclave_name}: No prior version of {report_title} found")

    @retry
    def add_indicators_to_object(self, indicators, report):
        self.globals_list["attribute_count"] += len(indicators)
        obj = MISPObject("trustar_report", standalone=False, strict=True)
        deeplink = f"https://station.trustar.co/constellation/reports/{report.id}"
        obj.comment = f"{report.title}\n\n{deeplink}"
        for indicator in indicators:
            try:
                misp_ioc = {
                    "value": indicator.value,
                    "first_seen": datetime_from_millis(indicator.first_seen),
                    "last_seen": datetime_from_millis(indicator.last_seen),
                }
                obj.add_attribute(indicator.type, **misp_ioc)
            except NewAttributeError:
                logger.info(
                    "Please upgrade your MISP instance to include Threat Actors"
                )
                continue
        self.globals_list["object_count"] += 1
        return obj

    @retry
    def add_indicators_to_event(self, event, indicators, enclave):
        self.globals_list["attribute_count"] += len(indicators)
        for indicator in indicators:
            ind_type = mappings["attributes"].get(indicator.type.upper())[
                "misp-attribute"
            ]
            tags = []
            if indicator.tags:
                for ind_tag in indicator.tags:
                    tag = MISPTag()
                    tag.name = ind_tag.name
                    tags.append(tag)
            attribute = MISPAttribute()
            attribute.type = ind_type
            attribute.value = indicator.value
            attribute.first_seen = datetime_from_millis(indicator.first_seen)
            attribute.last_seen = datetime_from_millis(indicator.last_seen)
            attribute.tags = tags
            event.Attribute.append(attribute)

        try:
            event = self.misp.update_event(event)

            if event.get("errors") is not None:
                logger.info(f"{event['errors'][0]}:{event['errors'][1]['message']}")
            else:
                logger.info(
                    f"{enclave['name']}: Added indicators to {event['Event']['info']} event"
                )

            if self.publish:
                self.misp.publish(event)
                logger.info("Published Event")
        except Exception as e:
            logger.exception(e)
            checkpoint(self.enclaves, self.completed_enclaves)
            raise

    @retry
    def use_case_3(self, event, reports, enclave):
        for report in reports:
            try:
                indicators = get_metadata(
                    list(ts.get_indicators_for_report(report.id)),
                    enclave["id"],
                )
            except HTTPError:
                logger.info(
                    f"{enclave['name']}: No indicators found for {report.title}"
                )
                continue

            self.check_old_events(report.title, enclave["name"])

            event.info = report.title
            event.distribution = self.distribution
            event.sharing_group_id = self.sharing_group
            event.threat_level_id = self.threat_level_id
            event.analysis = self.analysis
            logger.info(
                f"{enclave['name']}: Generating a MISP fixed event for {event.info}"
            )

            event.add_tag({"name": "trustar", "colour": "#3568D5"})
            event.add_tag({"name": enclave["name"]})
            """
            enclave_names = [enclave["name"].strip() for enclave in self.enclaves]
            for name in enclave_names:
                event.add_tag({"name": name})
            """
            for tag in ts.get_enclave_tags(report.id):
                event.add_tag(tag.name)
                logger.info(f"{tag.name} added to event")

            logger.info(
                f"{enclave['name']}: Adding indicators to MISP object for {event.info}"
            )
            obj = self.add_indicators_to_object(indicators, report)
            event.add_object(obj)

            try:
                self.misp.add_event(event)
                self.globals_list["event_count"] += 1
                logger.info(f"{enclave['name']}: Submitted MISP event: {event['info']}")
                if self.publish:
                    self.misp.publish(event)
                    logger.info("Published event")
                event = MISPEvent()
            except Exception as e:
                checkpoint(self.enclaves, self.completed_enclaves)
                logger.exception(e)
                raise

    @retry
    def use_case_2(self, event, reports, enclave):
        for report in reports:
            try:
                indicators = get_metadata(
                    list(ts.get_indicators_for_report(report.id)),
                    enclave["id"],
                )
            except HTTPError:
                logger.info(
                    f"{enclave['name']}: No indicators found for {report.title}"
                )
                continue

            logger.info(
                f"{enclave['name']}: Adding indicators to MISP object for {event.info}"
            )
            obj = self.add_indicators_to_object(indicators, report)
            event.add_object(obj)

        try:
            event = self.misp.update_event(event)
            if self.publish:
                self.misp.publish(event)
                logger.info("Published Event")
            logger.info(
                f"{enclave['name']}: Added {report.title} object to MISP event: {event['Event']['info']}"
            )
        except Exception as e:
            checkpoint(self.enclaves, self.completed_enclaves)
            logger.exception(e)
            raise

    @retry
    def use_case_1(self, event, indicators, enclave):
        logger.info(f"{enclave['name']}: Adding indicators for {event.info}")
        self.add_indicators_to_event(event, indicators, enclave)

    def ts_reports_to_misp(self):
        try:
            for enclave in self.enclaves:
                if enclave["use_case"] != 3:
                    event = self.misp_event(enclave)
                    self.globals_list["event_count"] += 1
                else:
                    event = MISPEvent()

                if enclave["use_case"] == 1:
                    logger.info(
                        f"{enclave['name']}: Use Case {enclave['use_case']} - searching for indicators from TruSTAR"
                    )
                    indicators = search_ts_indicators(
                        enclave, self.from_time, self.to_time
                    )
                    if not indicators:
                        logger.info(
                            f"No indicators for {enclave['name']} for the given time period, onto the next enclave"
                        )
                        self.completed_enclaves.append(enclave)
                        continue

                    self.use_case_1(event, indicators, enclave)
                else:
                    logger.info(
                        f"{enclave['name']}: Use Case {enclave['use_case']} - searching for reports from TruSTAR"
                    )
                    reports = search_ts_reports(enclave, self.from_time, self.to_time)
                    if not reports:
                        logger.info(
                            f"No reports found for {enclave['name']} for the given time period, onto the next enclave"
                        )
                        self.completed_enclaves.append(enclave)
                        continue

                    if enclave["use_case"] == 3:
                        self.use_case_3(event, reports, enclave)
                    elif enclave["use_case"] == 2:
                        self.use_case_2(event, reports, enclave)
                self.completed_enclaves.append(enclave)
        except Exception as e:
            # Generic exception handler prevents me from writing duplicate code for checkpointing
            checkpoint(self.enclaves, self.completed_enclaves)
            logger.exception(
                "Please re-run this query with the following added parameter: -c"
            )
            logger.exception(e)
            raise


def main():
    ts_misp.ts_reports_to_misp()
    end_time = datetime.now()
    logger.info(f"TruSTAR-MISP Connector - Complete: {end_time}")
    logger.info(f"Elapsed time: {end_time - start_time}")
    logger.info(f"Events: {ts_misp.globals_list['event_count']}")
    logger.info(f"Objects: {ts_misp.globals_list['object_count']}")
    logger.info(f"Attributes: {ts_misp.globals_list['attribute_count']}")


if __name__ == "__main__":
    """
    Pulls down all reports from TruSTAR for the last 24 hours,
    generates a MISP event for each of those reports,
    adds the TruSTAR indicators and tags to the event, and submits to MISP
    """
    start_time = datetime.now()
    logger.info(f"TruSTAR-MISP Enclave Ingest - Start Time: {start_time}")
    logger.info("Initializing TruSTAR Python SDK")
    ts_config = config_from_file("trustar.conf", "trustar")
    ts = TruStar(
        config={
            "user_api_key": ts_config["user_api_key"],
            "user_api_secret": ts_config["user_api_secret"],
            "client_metatag": ts_config["client_metatag"],
        }
    )

    logger.info("Parsing command-line arguments")
    args = get_cl_args()

    logger.info("Initializing MISP connection")
    disable_warnings(InsecureRequestWarning)

    misp = PyMISP(
        args.misp_url,
        args.misp_key,
        args.misp_verifycert,
    )

    ts_misp = TruStarMISP(
        misp,
        args.enclaves,
        args.from_time,
        args.to_time,
        args.distribution,
        args.threat_level_id,
        args.analysis,
        args.sharing_group,
        args.publish,
    )

    main()
