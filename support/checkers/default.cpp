#include "testlib.h"

#include <string>
#include <vector>

using namespace std;

static bool hasUtf8Bom(const string& s) {
    return s.size() >= 3 &&
           static_cast<unsigned char>(s[0]) == 0xEF &&
           static_cast<unsigned char>(s[1]) == 0xBB &&
           static_cast<unsigned char>(s[2]) == 0xBF;
}

static string normalizeLine(string line, bool isFirstLine) {
    if (isFirstLine && hasUtf8Bom(line))
        line.erase(0, 3);

    while (!line.empty()) {
        char ch = line.back();
        if (ch == ' ' || ch == '\t' || ch == '\r' || ch == '\f' || ch == '\v')
            line.pop_back();
        else
            break;
    }

    return line;
}

static vector<string> readNormalizedLines(InStream& in) {
    vector<string> lines;

    while (!in.eof()) {
        string line = in.readLine();
        if (line.empty() && in.eof())
            break;
        lines.push_back(normalizeLine(line, lines.empty()));
    }

    while (!lines.empty() && lines.back().empty())
        lines.pop_back();

    return lines;
}

int main(int argc, char* argv[]) {
    setName("NOIP default checker: ignore trailing spaces and line endings");
    registerTestlibCmd(argc, argv);

    vector<string> expected = readNormalizedLines(ans);
    vector<string> found = readNormalizedLines(ouf);

    size_t common = min(expected.size(), found.size());
    for (size_t i = 0; i < common; ++i) {
        if (expected[i] != found[i]) {
            quitf(_wa, "%d%s lines differ - expected: '%s', found: '%s'",
                  int(i + 1), englishEnding(int(i + 1)).c_str(),
                  compress(expected[i]).c_str(), compress(found[i]).c_str());
        }
    }

    if (expected.size() != found.size()) {
        size_t lineNo = common + 1;
        const string& exp = (lineNo <= expected.size() ? expected[lineNo - 1] : string("<EOF>"));
        const string& got = (lineNo <= found.size() ? found[lineNo - 1] : string("<EOF>"));
        quitf(_wa, "%d%s lines differ - expected: '%s', found: '%s'",
              int(lineNo), englishEnding(int(lineNo)).c_str(),
              compress(exp).c_str(), compress(got).c_str());
    }

    if (expected.size() == 1)
        quitf(_ok, "single line: '%s'", compress(expected[0]).c_str());

    quitf(_ok, "%d lines", int(expected.size()));
}
