#include "httplib.h"
#include <windows.h>

std::string log(const httplib::Request& req, const httplib::Response& res)
{
	std::string s;
	char buf[BUFSIZ];

	s += "================================\n";

	snprintf(buf, sizeof(buf), "%s %s %s", req.method.c_str(), req.version.c_str(), req.path.c_str());
	s += buf;

	std::string query;
	for (auto it = req.params.begin(); it != req.params.end(); ++it) {
		const auto& x = *it;
		snprintf(buf, sizeof(buf), "%c%s=%s",
			(it == req.params.begin()) ? '?' : '&', x.first.c_str(), x.second.c_str());
		query += buf;
	}
	snprintf(buf, sizeof(buf), "%s\n", query.c_str());
	s += buf;

	s += "--------------------------------\n";

	snprintf(buf, sizeof(buf), "%d %s\n", res.status, res.version.c_str());
	s += buf;
	s += "\n";

	if (!res.body.empty()) {
		s += res.body;
	}

	s += "\n";

	return s;
}

const char *pubServerInfo = R"----(
{
  "regions": [
    {
      "id": 11,
      "services": [
        {
          "pubkey": "WY*Nhx$kk@PTTz7Ykp*t!q#*8taRR84ZnyT7Rjqc%^39!7zx5GdYa!HSmpM^KQ!D",
          "url": "https://ap-southeast-2-prod-prodpc01-reg-bps-gatewayreg.p76prod.systems",
          "name": "bps-gatewayreg"
        }
      ],
      "ping_url": "https://ap-southeast-2-prod-prodpc01-reg-httpping.p76prod.systems/ping"
    },
    {
      "id": 6,
      "services": [
        {
          "pubkey": "WY*Nhx$kk@PTTz7Ykp*t!q#*8taRR84ZnyT7Rjqc%^39!7zx5GdYa!HSmpM^KQ!D",
          "url": "https://eu-central-1-prod-prodpc01-reg-bps-gatewayreg.p76prod.systems",
          "name": "bps-gatewayreg"
        }
      ],
      "ping_url": "https://eu-central-1-prod-prodpc01-reg-httpping.p76prod.systems/ping"
    },
    {
      "id": 7,
      "services": [
        {
          "pubkey": "WY*Nhx$kk@PTTz7Ykp*t!q#*8taRR84ZnyT7Rjqc%^39!7zx5GdYa!HSmpM^KQ!D",
          "url": "https://eu-west-1-prod-prodpc01-reg-bps-gatewayreg.p76prod.systems",
          "name": "bps-gatewayreg"
        }
      ],
      "ping_url": "https://eu-west-1-prod-prodpc01-reg-httpping.p76prod.systems/ping"
    },
    {
      "id": 8,
      "services": [
        {
          "pubkey": "WY*Nhx$kk@PTTz7Ykp*t!q#*8taRR84ZnyT7Rjqc%^39!7zx5GdYa!HSmpM^KQ!D",
          "url": "https://eu-west-2-prod-prodpc01-reg-bps-gatewayreg.p76prod.systems",
          "name": "bps-gatewayreg"
        }
      ],
      "ping_url": "https://eu-west-2-prod-prodpc01-reg-httpping.p76prod.systems/ping"
    },
    {
      "id": 2,
      "services": [
        {
          "pubkey": "WY*Nhx$kk@PTTz7Ykp*t!q#*8taRR84ZnyT7Rjqc%^39!7zx5GdYa!HSmpM^KQ!D",
          "url": "https://us-east-1-prod-prodpc01-reg-bps-gatewayreg.p76prod.systems",
          "name": "bps-gatewayreg"
        }
      ],
      "ping_url": "https://us-east-1-prod-prodpc01-reg-httpping.p76prod.systems/ping"
    },
    {
      "id": 3,
      "services": [
        {
          "pubkey": "WY*Nhx$kk@PTTz7Ykp*t!q#*8taRR84ZnyT7Rjqc%^39!7zx5GdYa!HSmpM^KQ!D",
          "url": "https://us-east-2-prod-prodpc01-reg-bps-gatewayreg.p76prod.systems",
          "name": "bps-gatewayreg"
        }
      ],
      "ping_url": "https://us-east-2-prod-prodpc01-reg-httpping.p76prod.systems/ping"
    },
    {
      "id": 5,
      "services": [
        {
          "pubkey": "WY*Nhx$kk@PTTz7Ykp*t!q#*8taRR84ZnyT7Rjqc%^39!7zx5GdYa!HSmpM^KQ!D",
          "url": "https://us-west-2-prod-prodpc01-reg-bps-gatewayreg.p76prod.systems",
          "name": "bps-gatewayreg"
        }
      ],
      "ping_url": "https://us-west-2-prod-prodpc01-reg-httpping.p76prod.systems/ping"
    }
  ],
  "global": {
    "services": [
      {
        "pubkey": "WY*Nhx$kk@PTTz7Ykp*t!q#*8taRR84ZnyT7Rjqc%^39!7zx5GdYa!HSmpM^KQ!D",
        "url": "https://us-east-2-prod-prodpc01-glb-bps-loginqueue.p76prod.systems",
        "name": "bps-loginqueue"
      },
      {
        "pubkey": "WY*Nhx$kk@PTTz7Ykp*t!q#*8taRR84ZnyT7Rjqc%^39!7zx5GdYa!HSmpM^KQ!D",
        "url": "https://us-east-2-prod-prodpc01-glb-bps-gateway.p76prod.systems",
        "name": "bps-gateway"
      },
      {
        "pubkey": "WY*Nhx$kk@PTTz7Ykp*t!q#*8taRR84ZnyT7Rjqc%^39!7zx5GdYa!HSmpM^KQ!D",
        "url": "https://us-east-2-prod-prodpc01-glb-bps-bigateway.p76prod.systems",
        "name": "bps-bigateway"
      },
      {
        "pubkey": "WY*Nhx$kk@PTTz7Ykp*t!q#*8taRR84ZnyT7Rjqc%^39!7zx5GdYa!HSmpM^KQ!D",
        "url": "http://localhost",
        "name": "bps-pushy"
      }
    ]
  }
})----";

void InitHttpServer(const char *Name, int Port)
{
	using namespace httplib;

	FILE *f;
	char filePath[MAX_PATH];

	sprintf_s(filePath, "C:\\%s.txt", Name);

	if (fopen_s(&f, filePath, "w") != 0)
		__debugbreak();

	setbuf(f, nullptr);

	Server svr;

	if (!svr.is_valid()) {
		fprintf(f, "[%s] Error initializing server\n", Name);
		return;
	}

	svr.set_logger([=](const Request& req, const Response& res) {
		fprintf(f, "[%s] FUCK\n", Name);
		fprintf(f, "[%s] %s", Name, log(req, res).c_str());
	});

	svr.Post("/fake/login", [=](const Request&, Response& res) {
		fprintf(f, "[%s] Fake login\n", Name);
		//res.set_content(R"----({"platform": {"message": "success", "code": 2000, "response": {"username": "lol" }}})----", "application/json");
		res.set_content(R"----({"access_token":"xxxxxxxx-0000-xxxx-xxxx-xxxxxxxxxxxx", "token":"xxxxxxxx-0000-xxxx-xxxx-xxxxxxxxxxxx", "resultname":"fakelogin"})----", "application/json");
	});

	svr.Post("/cms/message", [=](const Request&, Response& res) {
		res.set_content(R"----({"platform": {"message": "success", "code": 2000, "response": [{"lang": "en", "content": "{ \n\"pre-login\": \"\nTest 1 worked!\", \n\n\"main-menu\": \"\nTest 2 worked!\", \n} \n  \n", "product_id": 10, "title": "B.E.T.A. Offline", "uauthor": "Contentful", "ctime": "2018-08-21T18:47:01.722000+00:00", "message_id": 1, "platform_id": 0, "version": "95", "type_id": 1, "cauthor": "Contentful", "public": 1, "utime": "2018-10-31T03:08:02.255000+00:00"}]}})----", "application/json");
	});

	svr.Post("/session/login", [=](const Request&, Response& res) {
		res.set_content(R"----({"platform": {"message": "success", "code": 2000, "response": {"username": "randomuser", "refresh_time": 1540087967, "application_id": "xxxxxxxx-4444-xxxx-xxxx-xxxxxxxxxxxx", "session_type": "basic", "external_account": {}, "buid": "xxxxxxxx-3333-xxxx-xxxx-xxxxxxxxxxxx", "time_to_refresh": 3600, "session_token": "123456789TOKEN", "time_to_expire": 7200, "exp": 1741101562, "master_account_id": "xxxxxxxx-2222-xxxx-xxxx-xxxxxxxxxxxx"}}})----", "application/json");
	});

	// GET
	svr.Get("/session/get-login-token", [=](const Request&, Response& res) {
		res.set_content(R"----({"platform": {"message": "success", "code": 2000, "response": "xxxxxxxx-1111-xxxx-xxxx-xxxxxxxxxxxx"}})----", "application/json");
	});

	// GET
	svr.Get("/notification/v1/system", [=](const Request&, Response& res) {
		res.set_content(R"----({"code":18000,"response":[{"id":16479,"name":"Friend","description":"Friend system"},{"id":11727,"name":"Presence","description":"Presence system"},{"id":1219,"name":"Matchmaking","description":"Matchmaking"},{"id":14301,"name":"VCCS","description":"Virtual Currency"}]})----", "application/json");
	});

	// GET
	svr.Get("/titlestorage/v1/products/my-product/platforms/pc/slots/1/branches/prodpc01", [=](const Request&, Response& res) {
		//res.set_content(R"----({"platform": {"message": "success", "code": 2000, "response": {"checksum": "cbe62c1ebffc7108f2e103f80ba0d3719df8d6e8efb3b1d51211a1cffe9ff2d2", "last_updated": "Wed Oct 31 19:01:38 2018", "download_url": "https://titlestorage.bethesda.net/public/1c6d662b-3ac3-465a-bdc8-bc67249b65cb/pc/1/prodpc01/a559599a5a21fd96b5866e18de4d5b4b", "size": 2793.0}}})----", "application/json");
		res.set_content(R"----({"platform": {"message": "success", "code": 2000, "response": {"checksum": "cbe62c1ebffc7108f2e103f80ba0d3719df8d6e8efb3b1d51211a1cffe9ff2d2", "last_updated": "Wed Oct 31 19:01:38 2018", "download_url": "http://localhost/public/1c6d662b-3ac3-465a-bdc8-bc67249b65cb/pc/1/prodpc01/a559599a5a21fd96b5866e18de4d5b4b", "size": 2793.0}}})----", "application/json");
	});

	svr.Post("/log/v3/collect_logdata", [=](const Request&, Response& res) {
		fprintf(f, "[%s] Ignoring log request\n", Name);
	});

	svr.Post("/log/collect_errordata", [=](const Request&, Response& res) {
		fprintf(f, "[%s] Ignoring log error request\n", Name);
	});


	// PUT
	svr.Put("/bps/pub/ticket", [=](const Request&, Response& res) {
		res.set_content(R"----({"ticket_token":"BPSPUBTICKETTOKEN","queue_pos":0,"poll_interval":1000000000})----", "application/json");
	});

	// POST
	svr.Post("/bps/pub/v2/login", [=](const Request&, Response& res) {
		res.set_content(R"----({"id":374603150323106951,"username":"randomuser","session_id":"xxxxxxxx-5555-xxxx-xxxx-xxxxxxxxxxxx","token":"BPSPUBV2LOGINTOKEN"})----", "application/json");
	});

	svr.Post("/bps/pub/bi/session/create", [=](const Request&, Response& res) {
		res.set_content(R"----({"token":"v1.PUBBISESSIONCREATETOKEN","level":9})----", "application/json");
	});

	// POST
	svr.Post("/bps/pub/v2/lobby/reconnect", [=](const Request&, Response& res) {
		res.set_header("X-BPS-Error", "1");
		res.set_header("X-Bps-Work-Id", "2d82016-0000-46a");
		res.set_content(R"----({"code":4011,"type":"NoLobbyLobbyError","msg":"","is_temporary":false})----", "application/json");
	});

	// GET
	svr.Get("/bps/pub/lobby", [=](const Request&, Response& res) {
		res.set_header("X-Bps-Error", "1");
		res.set_header("X-Bps-Work-Id", "2d82016-97f4-46a");
		res.set_content(R"----({"code":4011,"type":"NoLobbyLobbyError","msg":"","is_temporary":false})----", "application/json");
	});

	// DELETE
	svr.Delete("/bps/pub/matchmake/request", [=](const Request&, Response& res) {
		res.set_content(R"----({})----", "application/json");
	});

	// POST
	svr.Post("/bps/pub/bi/session/event/bulk", [=](const Request&, Response& res) {
		res.set_content(R"----({})----", "application/json");
	});

	svr.Get("/public/1c6d662b-3ac3-465a-bdc8-bc67249b65cb/pc/1/prodpc01/a559599a5a21fd96b5866e18de4d5b4b", [=](const Request&, Response& res) {
		res.set_content(pubServerInfo, "application/json");
	});

	// GET
	svr.Get("/social/v3/friends", [=](const Request&, Response& res) {
		res.set_content(R"----({"code": 16000, "response": {"friend_list": [], "total_count": 0}})----", "application/json");
	});

	// GET
	svr.Get("/bps/pub/character/list", [=](const Request&, Response& res) {
		res.set_content(R"----({"characters":[{"id":974803173767959590,"name":"TestAccount","level":8,"is_complete":true,"created":1440889858542,"updated":1440851618852,"region":2}]})----", "application/json");
	});

	// POST
	svr.Post("/bps/pub/matchmake/find", [=](const Request&, Response& res) {
		res.set_content(R"----({"request_id":"xxxxxxxx-6666-xxxx-xxxx-xxxxxxxxxxxx","at_cap":false,"cooldown_sec":300})----", "application/json");
	});

	fprintf(f, "[%s] Initialized on port %d\n", Name, Port);
	svr.listen("localhost", Port);

	fclose(f);
}

void InitServerThreads()
{
	auto runThreaded = [](const char *Name, int Port)
	{
		std::thread t([=]()
		{
			InitHttpServer(Name, Port);
		});

		t.detach();
	};

	//
	// http://127.0.0.1:8005	sGatewayServer
	// http://127.0.0.1:8006	sLoginServer
	// http://127.0.0.1:8007	sBIGatewayServer
	// ws://127.0.0.1:8008		sPushyServer
	// http://127.0.0.1:8014	sLoginQueueServer
	// http://127.0.0.1:8018	sRegionalGatewayServer
	//
	runThreaded("GatewayServer", 8005);
	runThreaded("LoginServer", 8006);
	runThreaded("BIGatewayServer", 8007);
	runThreaded("PushyServer", 8008);
	runThreaded("CRServer", 8010);
	runThreaded("LoginQueueServer", 8014);
	runThreaded("RegionalGatewayServer", 8018);
	runThreaded("HTTP", 80);
	runThreaded("HTTP8080", 8080);
	runThreaded("HTTPS", 443);
}