'use strict';

const Code = require('code');
const Lab = require('lab');
const DataRetrievalRouter = require('../').DataRetrievalRouter;

const lab = exports.lab = Lab.script();
const experiment = lab.experiment;
const test = lab.test;

const expect = Code.expect;

/**
 * Rule based access control policy tests, based on username
 **/
experiment('RBAC internal modular information retrieval', () => {

    const dataRetriever = new DataRetrievalRouter();

    test('should register a valid retriever', (done) => {

        const retriever = (source, key, context) => {

            return 'key-' + key;
        };

        dataRetriever.register('test', retriever);

        dataRetriever.get('test:x', (err, result) => {

            expect(err).to.not.exist();
            expect(result).to.equal('key-x');
            done();
        });
    });

    test('should override a valid retriever (single handler)', (done) => {

        const retriever1 = (source, key, context) => {

            return key + '-1';
        };

        const retriever2 = (source, key, context) => {

            return key + '-2';
        };

        dataRetriever.register('test-override', retriever1);
        dataRetriever.register('test-override', retriever2, { override: true });

        dataRetriever.get('test-override:test', (err, result) => {

            expect(err).to.not.exist();
            expect(result).to.equal('test-2');

            done();
        });

    });

    test('should not override a valid retriever (single handler)', (done) => {

        const retriever1 = (source, key, context) => {

            return key + '-1';
        };

        const retriever2 = (source, key, context) => {

            return key + '-2';
        };

        dataRetriever.register('test-override-error', retriever1);

        expect(dataRetriever.register.bind(dataRetriever, 'test-override-error', retriever2)).to.throw();

        done();
    });

    test('should override a valid retriever (multiple handlers)', (done) => {

        const retriever1 = (source, key, context) => {

            return key + '-1';
        };

        const retriever2 = (source, key, context) => {

            return key + '-2';
        };

        dataRetriever.register(['test-override-multiple-1', 'test-override-multiple-2', 'test-override-multiple-3'], retriever1);
        dataRetriever.register(['test-override-multiple-2', 'test-override-multiple-4'], retriever2, { override: true }); // test-override-multiple-2 collides

        dataRetriever.get('test-override-multiple-1:test', (err, result) => {

            expect(err).to.not.exist();
            expect(result).to.equal('test-1');

            dataRetriever.get('test-override-multiple-2:test', (err, result) => {

                expect(err).to.not.exist();
                expect(result).to.equal('test-2');


                dataRetriever.get('test-override-multiple-3:test', (err, result) => {

                    expect(err).to.not.exist();
                    expect(result).to.equal('test-1');

                    dataRetriever.get('test-override-multiple-4:test', (err, result) => {

                        expect(err).to.not.exist();
                        expect(result).to.equal('test-2');

                        done();
                    });
                });
            });
        });
    });

    test('should not override a valid retriever (multiple handlers)', (done) => {

        const retriever1 = (source, key, context) => {

            return key + '-1';
        };

        const retriever2 = (source, key, context) => {

            return key + '-2';
        };

        dataRetriever.register(['test-override-error-multiple-1', 'test-override-error-multiple-2', 'test-override-error-multiple-3'], retriever1);
        expect(dataRetriever.register.bind(dataRetriever, ['test-override-error-multiple-2', 'test-override-error-multiple-4'], retriever2)).to.throw(Error, 'There is a data retriever already registered for the source: test-override-error-multiple-2');

        done();
    });

    test('should register a valid asynchronous retriever', (done) => {

        const retriever = (source, key, context, callback) => {

            callback(null, 'key-' + key);
        };

        dataRetriever.register('async-test', retriever);

        dataRetriever.get('async-test:x', (err, result) => {

            expect(err).to.not.exist();
            expect(result).to.equal('key-x');
            done();
        });
    });

    test('should use parent asynchronous retriever', (done) => {

        const retriever = (source, key, context, callback) => {

            callback(null, 'key-' + key);
        };

        dataRetriever.register('async-parent-test-1', retriever);

        const childDataRetriever = dataRetriever.createChild();

        childDataRetriever.get('async-parent-test-1:x', (err, result) => {

            expect(err).to.not.exist();
            expect(result).to.equal('key-x');
            done();
        });
    });

    test('should use parent synchronous retriever', (done) => {

        const retriever = (source, key, context) => {

            return 'key-' + key;
        };

        dataRetriever.register('sync-parent-test-1', retriever);

        const childDataRetriever = dataRetriever.createChild();

        childDataRetriever.get('sync-parent-test-1:x', (err, result) => {

            expect(err).to.not.exist();
            expect(result).to.equal('key-x');
            done();
        });
    });

    test('should return null if inexistent prefix on child and parent', (done) => {

        const childDataRetriever = dataRetriever.createChild();

        childDataRetriever.get('this-does-not-exist-1:x', (err, result) => {

            expect(err).to.not.exist();
            expect(result).to.not.exist();
            done();
        });
    });

    test('should not allow using get with context and without callback', (done) => {

        expect(dataRetriever.get.bind(null, 'get-with-context-without-callback:x', {})).to.throw(Error);
        done()
    });

    test('should not allow using get without context and without callback', (done) => {

        expect(dataRetriever.get.bind(null, 'get-with-context-without-callback:x', {})).to.throw(Error);
        done()
    });

    test('should return err in callback when an error is thrown (sync)', (done) => {

        const retriever = (source, key, context) => {

            throw new Error('test');
        };

        dataRetriever.register('sync-test-err-1', retriever);

        dataRetriever.get('sync-test-err-1:x', (err, result) => {

            expect(err).to.exist();

            done();
        });
    });

    test('should return err in callback when an error is thrown (async)', (done) => {

        const retriever = (source, key, context, callback) => {

            throw new Error('test');
        };

        dataRetriever.register('async-test-err-1', retriever);

        dataRetriever.get('async-test-err-1:x', (err, result) => {

            expect(err).to.exist();

            done();
        });
    });
});
