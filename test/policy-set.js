'use strict';

const Code = require('code');
const Lab = require('lab');

const lab = exports.lab = Lab.script();
const experiment = lab.experiment;
const test = lab.test;

const expect = Code.expect;

const Rbac = require('../');
const DataRetrievalRouter = require('../lib/DataRetrievalRouter');


experiment('Policy set unit tests', () => {

    const dataRetriever = new DataRetrievalRouter();
    dataRetriever.register('credentials', (source, key, context) => {

        return context[key];
    }, { override: true });

    const policySet = {
        target: [{ 'credentials:group': 'writer' }, { 'credentials:group': 'publisher' }], // writer OR publisher
        apply: 'permit-overrides', // deny, unless one permits
        policies: [
            {
                target: [{ 'credentials:group': 'writer', 'credentials:premium': true }], // if writer AND premium account
                apply: 'deny-overrides', // permit, unless one denies
                rules: [
                    {
                        target: { 'credentials:username': 'bad_user' }, // if the username is bad_user (no need for array)
                        effect: 'deny'  // then deny
                    },
                    {
                        target: { 'credentials:blocked': true }, // if the user is blocked (no need for array)
                        effect: 'deny'  // then deny
                    },
                    {
                        effect: 'permit' // else permit
                    }
                ]
            },
            {
                target: { 'credentials:premium': false }, // if (writer OR publisher) AND no premium account
                apply: 'permit-overrides', // deny, unless one permits
                rules: [
                    {
                        target: { 'credentials:username': 'special_user' }, // if the username is special_user
                        effect: 'permit'  // then permit
                    },
                    {
                        effect: 'deny' // else deny
                    }
                ]
            }
        ]
    };

    test('should permit premium writer', (done) => {

        const information = {
            username: 'user00001',
            group: ['writer'],
            premium: true,
            blocked: false
        };

        Rbac.evaluatePolicy(policySet, dataRetriever.createChild(information), (err, applies) => {

            expect(err).to.not.exist();

            expect(applies).to.exist().and.to.equal(Rbac.PERMIT);

            done();
        });
    });

    test('should deny blocked premium writer', (done) => {

        const information = {
            username: 'bad_user',
            group: ['writer'],
            premium: true,
            blocked: false
        };

        Rbac.evaluatePolicy(policySet, dataRetriever.createChild(information), (err, applies) => {

            expect(err).to.not.exist();

            expect(applies).to.exist().and.to.equal(Rbac.DENY);

            done();
        });
    });

    test('should deny publisher without premium', (done) => {

        const information = {
            username: 'user00002',
            group: ['publisher'],
            premium: false,
            blocked: false
        };

        Rbac.evaluatePolicy(policySet, dataRetriever.createChild(information), (err, applies) => {

            expect(err).to.not.exist();

            expect(applies).to.exist().and.to.equal(Rbac.DENY);

            done();
        });
    });

    test('should permit special publisher without premium', (done) => {

        const information = {
            username: 'special_user',
            group: ['publisher'],
            premium: false,
            blocked: false
        };

        Rbac.evaluatePolicy(policySet, dataRetriever.createChild(information), (err, applies) => {

            expect(err).to.not.exist();

            expect(applies).to.exist().and.to.equal(Rbac.PERMIT);

            done();
        });
    });

    test('should permit special writer without premium', (done) => {

        const information = {
            username: 'special_user',
            group: ['writer'],
            premium: false,
            blocked: false
        };

        Rbac.evaluatePolicy(policySet, dataRetriever.createChild(information), (err, applies) => {

            expect(err).to.not.exist();

            expect(applies).to.exist().and.to.equal(Rbac.PERMIT);

            done();
        });
    });

    test('should permit special publisher and writer without premium', (done) => {

        const information = {
            username: 'special_user',
            group: ['writer', 'publisher'],
            premium: false,
            blocked: false
        };

        Rbac.evaluatePolicy(policySet, dataRetriever.createChild(information), (err, applies) => {

            expect(err).to.not.exist();

            expect(applies).to.exist().and.to.equal(Rbac.PERMIT);

            done();
        });
    });

    test('should deny publisher with premium', (done) => {

        const information = {
            username: 'user00003',
            group: ['publisher'],
            premium: true,
            blocked: false
        };

        Rbac.evaluatePolicy(policySet, dataRetriever.createChild(information), (err, applies) => {

            expect(err).to.not.exist();

            expect(applies).to.exist().and.to.equal(Rbac.DENY);

            done();
        });
    });

    test('should have error on missing policy', (done) => {

        const information = {
            username: 'user00003',
            group: ['publisher'],
            premium: true,
            blocked: false
        };

        Rbac.evaluatePolicy(null, dataRetriever.createChild(information), (err, applies) => {

            expect(err).to.exist();

            done();
        });
    });

    test('should have error on missing data retriever', (done) => {

        Rbac.evaluatePolicy(policySet, null, (err, applies) => {

            expect(err).to.exist();

            done();
        });
    });

    test('should have error on invalid data retriever', (done) => {

        Rbac.evaluatePolicy(policySet, 'test', (err, applies) => {

            expect(err).to.exist();

            done();
        });
    });

    test('should have error on invalid combinatory algorithm', (done) => {

        const invalidPolicySet = {
            target: [{ 'credentials:group': 'writer' }, { 'credentials:group': 'publisher' }], // writer OR publisher
            apply: 'some-strange-value',
            rules: [
                {
                    effect: 'deny'
                }
            ]
        };

        Rbac.evaluatePolicy(invalidPolicySet, dataRetriever, (err, applies) => {

            expect(err).to.exist();

            done();
        });
    });

});
