describe('wasm test local', () => {
  it('tests pass', async () => {
    // await browser.url("http://localhost:8080/src/wasm/test/test.html?threaded=false&bench=false");
    await browser.url("http://localhost:8080/src/wasm/test/test_noworker.html");
    await browser.waitUntil(
      async () => (await browser.getTitle()).match("strand wasm test"),
      5000,
      "Title didn't match"
    );

    const lognew = await $('#lognew');

    await browser.waitUntil(
      async () => (await lognew.getText()) === "ok", 
      { 
        timeout: 5000,
        timeoutMsg: 'Get text timeout' 
      }
    );
  
  });
});
