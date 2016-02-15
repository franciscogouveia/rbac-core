'use strict';

const Code = require('code');
const Lab = require('lab');

const lab = exports.lab = Lab.script();
const experiment = lab.experiment;
const test = lab.test;

const expect = Code.expect;

const Rbac = require('../');
const DataRetrievalRouter = require('../lib/DataRetrievalRouter');


experiment('Rule unit tests (permit)', () => {

    const rule = {
        target: [{ 'credentials:group': ['administrator', 'publisher'] }], // administrator AND publisher -> never use the same key twice in an object or it will be overriden
        effect: 'permit'
    };

    // Register mocked data retriever
    const dataRetriever = new DataRetrievalRouter();
    dataRetriever.register('credentials', (source, key, context) => {

        return context[key];
    }, { override: true });

    test('should permit publisher administrator', (done) => {

        const information = {
            username: 'user00001',
            group: ['administrator', 'publisher']
        };

        Rbac.evaluatePolicy(rule, dataRetriever.createChild(information), (err, result) => {

            expect(err).to.not.exist();

            expect(result).to.exist().and.to.equal(Rbac.PERMIT);

            done();
        });
    });

    test('should be undetermined access to publisher', (done) => {

        const information = {
            username: 'user00002',
            group: ['publisher']
        };

        Rbac.evaluatePolicy(rule, dataRetriever.createChild(information), (err, result) => {

            expect(err).to.not.exist();

            expect(result).to.exist().and.to.equal(Rbac.UNDETERMINED);

            done();
        });
    });

    test('should be undetermined access to administrator', (done) => {

        const information = {
            username: 'user00003',
            group: ['administrator']
        };

        Rbac.evaluatePolicy(rule, dataRetriever.createChild(information), (err, result) => {

            expect(err).to.not.exist();

            expect(result).to.exist().and.to.equal(Rbac.UNDETERMINED);

            done();
        });
    });

});

experiment('Rule unit tests (deny)', () => {

    const rule = {
        target: [
            { 'credentials:group': 'blacklist' }, // Blacklisted OR
            { 'credentials:group': 'anonymous' }, // Anonymous OR
            { 'credentials:verified': false } // Not verified
        ],
        effect: 'deny'
    };

    // Register mocked data retriever
    const dataRetriever = new DataRetrievalRouter();
    dataRetriever.register('credentials', (source, key, context) => {

        return context[key];
    }, { override: true });

    test('should deny user in blacklist group', (done) => {

        const information = {
            username: 'user00001',
            group: ['blacklist', 'publisher'],
            verified: true
        };

        Rbac.evaluatePolicy(rule, dataRetriever.createChild(information), (err, result) => {

            expect(err).to.not.exist();

            expect(result).to.exist().and.to.equal(Rbac.DENY);

            done();
        });
    });

    test('should deny user in anonymous group', (done) => {

        const information = {
            username: 'user00001',
            group: ['anonymous'],
            verified: true
        };

        Rbac.evaluatePolicy(rule, dataRetriever.createChild(information), (err, result) => {

            expect(err).to.not.exist();

            expect(result).to.exist().and.to.equal(Rbac.DENY);

            done();
        });
    });

    test('should deny not verified user', (done) => {

        const information = {
            username: 'user00001',
            group: ['administrator', 'publisher'],
            verified: false
        };

        Rbac.evaluatePolicy(rule, dataRetriever.createChild(information), (err, result) => {

            expect(err).to.not.exist();

            expect(result).to.exist().and.to.equal(Rbac.DENY);

            done();
        });
    });

    test('should be undetermined', (done) => {

        const information = {
            username: 'user00001',
            group: ['administrator', 'publisher'],
            verified: true
        };

        Rbac.evaluatePolicy(rule, dataRetriever.createChild(information), (err, result) => {

            expect(err).to.not.exist();

            expect(result).to.exist().and.to.equal(Rbac.UNDETERMINED);

            done();
        });
    });

});

experiment('Rule unit tests', () => {

    // Register mocked data retriever
    const dataRetriever = new DataRetrievalRouter();

    test('should have error on missing rule', (done) => {

        Rbac.evaluateRule(null, dataRetriever, (err, result) => {

            expect(err).to.exist();

            done();
        });
    });

    test('should have error on missing effect', (done) => {

        const invalidRule = {
            target: [{ 'credentials:group': ['administrator', 'publisher'] }] // administrator AND publisher -> never use the same key twice in an object or it will be overriden
        };

        Rbac.evaluateRule(invalidRule, dataRetriever, (err, result) => {

            expect(err).to.exist();

            done();
        });
    });

    test('should have error on invalid effect', (done) => {

        const invalidRule = {
            target: [{ 'credentials:group': ['administrator', 'publisher'] }], // administrator AND publisher -> never use the same key twice in an object or it will be overriden
            effect: 'some-strange-value'
        };

        Rbac.evaluateRule(invalidRule, dataRetriever, (err, result) => {

            expect(err).to.exist();

            done();
        });
    });
});
