#include "clientLogic.h"

ClientLogic clientLogic;

// entry point
int main() {
	cout << "Starting registration" << endl;
	// registration
	clientLogic.startClient();

	cout << "Starting reconnect" << endl;
	// reconnect
	clientLogic.startClient();

	return 0;
}