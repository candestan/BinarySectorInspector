#pragma once

// welcome footer quotes. not i18n.
// empty by -> print "text" only.

struct WelcomeQuote
{
    const char* text;
    const char* by;
};

static const WelcomeQuote kWelcomeQuotes[] = {
    { "Trust, but verify the PE.", "candestan" },
    { "Packers lie. Hex doesn't.", "candestan" },
};

static const int kWelcomeQuoteCount = (int)(sizeof(kWelcomeQuotes) / sizeof(kWelcomeQuotes[0]));
