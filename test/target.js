'use strict';

const Code = require('code');
const Lab = require('lab');

const lab = exports.lab = Lab.script();
const experiment = lab.experiment;
const test = lab.test;

const expect = Code.expect;

const Rbac = require('../');
const DataRetrievalRouter = require('../lib/DataRetrievalRouter');


experiment('Target unit tests (AND)', () => {

    const target = { 'credentials:group': 'writer', 'credentials:premium': true };

    // Register mocked data retriever
    const dataRetriever = new DataRetrievalRouter();
    dataRetriever.register('credentials', (source, key, context) => {

        return context[key];
    }, { override: true });

    test('should apply (full match)', (done) => {

        const information = {
            username: 'user00001',
            group: ['writer'],
            premium: true
        };

        Rbac.evaluateTarget(target, dataRetriever.createChild(information), (err, applies) => {

            expect(err).to.not.exist();

            expect(applies).to.exist().and.to.equal(true);

            done();
        });
    });

    test('should not apply (partial match)', (done) => {

        const information = {
            username: 'user00002',
            group: ['writer'],
            premium: false
        };

        Rbac.evaluateTarget(target, dataRetriever.createChild(information), (err, applies) => {

            expect(err).to.not.exist();

            expect(applies).to.exist().and.to.equal(false);

            done();
        });
    });

    test('should not apply (no match)', (done) => {

        const information = {
            username: 'user00003',
            group: ['reader'],
            premium: false
        };

        Rbac.evaluateTarget(target, dataRetriever.createChild(information), (err, applies) => {

            expect(err).to.not.exist();

            expect(applies).to.exist().and.to.equal(false);

            done();
        });
    });

});

experiment('Target unit tests (AND with RegExp)', () => {

    const target = { 'credentials:group': /^articles\:(writer|reader)$/, 'credentials:premium': true };

    // Register mocked data retriever
    const dataRetriever = new DataRetrievalRouter();
    dataRetriever.register('credentials', (source, key, context) => {

        return context[key];
    }, { override: true });

    test('should apply (full match: articles:writer)', (done) => {

        const information = {
            username: 'user00001',
            group: ['articles:writer'],
            premium: true
        };

        Rbac.evaluateTarget(target, dataRetriever.createChild(information), (err, applies) => {

            expect(err).to.not.exist();

            expect(applies).to.exist().and.to.equal(true);

            done();
        });
    });

    test('should apply (full match: articles:reader)', (done) => {

        const information = {
            username: 'user00002',
            group: ['articles:reader'],
            premium: true
        };

        Rbac.evaluateTarget(target, dataRetriever.createChild(information), (err, applies) => {

            expect(err).to.not.exist();

            expect(applies).to.exist().and.to.equal(true);

            done();
        });
    });

    test('should not apply (partial match)', (done) => {

        const information = {
            username: 'user00003',
            group: ['articles:other'],
            premium: true
        };

        Rbac.evaluateTarget(target, dataRetriever.createChild(information), (err, applies) => {

            expect(err).to.not.exist();

            expect(applies).to.exist().and.to.equal(false);

            done();
        });
    });

    test('should not apply (no match)', (done) => {

        const information = {
            username: 'user00004',
            group: ['articles:other'],
            premium: false
        };

        Rbac.evaluateTarget(target, dataRetriever.createChild(information), (err, applies) => {

            expect(err).to.not.exist();

            expect(applies).to.exist().and.to.equal(false);

            done();
        });
    });

});


experiment('Target unit tests (AND with field agains field matching)', () => {

    const target = { 'credentials:group': 'writer', 'credentials:some-field': { field: 'external:some-field-name' } };

    // Register mocked data retrievers
    const dataRetriever = new DataRetrievalRouter();
    dataRetriever.register('credentials', (source, key, context) => context[key], { override: true });

    const externalContext = { 'some-field-name': 'some-field-value' };
    dataRetriever.register('external', (source, key, context) => externalContext[key], { override: true });

    test('should apply (full match)', (done) => {

        const information = {
            username: 'user00001',
            group: ['writer'],
            'some-field': 'some-field-value'
        };

        Rbac.evaluateTarget(target, dataRetriever.createChild(information), (err, applies) => {

            expect(err).to.not.exist();

            expect(applies).to.exist().and.to.equal(true);

            done();
        });
    });

    test('should not apply (partial match)', (done) => {

        const information = {
            username: 'user00002',
            group: ['writer'],
            'some-field': 'bad-field-value'
        };

        Rbac.evaluateTarget(target, dataRetriever.createChild(information), (err, applies) => {

            expect(err).to.not.exist();

            expect(applies).to.exist().and.to.equal(false);

            done();
        });
    });

    test('should not apply (no match)', (done) => {

        const information = {
            username: 'user00003',
            group: ['reader'],
            'some-field': 'bad-field-value'
        };

        Rbac.evaluateTarget(target, dataRetriever.createChild(information), (err, applies) => {

            expect(err).to.not.exist();

            expect(applies).to.exist().and.to.equal(false);

            done();
        });
    });

});

experiment('Target unit tests (OR)', () => {

    const target = [
        { 'credentials:group': 'writer' },
        { 'credentials:premium': true },
        { 'credentials:username': 'user00002' }
    ];

    // Register mocked data retriever
    const dataRetriever = new DataRetrievalRouter();
    dataRetriever.register('credentials', (source, key, context) => {

        return context[key];
    }, { override: true });

    test('should apply (partial match)', (done) => {

        const information = {
            username: 'user00001', // do not match
            group: ['writer'],
            premium: true
        };

        Rbac.evaluateTarget(target, dataRetriever.createChild(information), (err, applies) => {

            expect(err).to.not.exist();

            expect(applies).to.exist().and.to.equal(true);

            done();
        });
    });

    test('should apply (full match)', (done) => {

        const information = {
            username: 'user00002',
            group: ['writer'],
            premium: true
        };

        Rbac.evaluateTarget(target, dataRetriever.createChild(information), (err, applies) => {

            expect(err).to.not.exist();

            expect(applies).to.exist().and.to.equal(true);

            done();
        });
    });

    test('should not apply (no match)', (done) => {

        const information = {
            username: 'user00003',
            group: ['reader'],
            premium: false
        };

        Rbac.evaluateTarget(target, dataRetriever.createChild(information), (err, applies) => {

            expect(err).to.not.exist();

            expect(applies).to.exist().and.to.equal(false);

            done();
        });
    });

});

experiment('Target unit tests', () => {

    const dataRetriever = new DataRetrievalRouter();

    test('should apply (partial match)', (done) => {

        const invalidTarget = [];

        Rbac.evaluateTarget(invalidTarget, dataRetriever, (err, applies) => {

            expect(err).to.exist();

            done();
        });
    });
});
