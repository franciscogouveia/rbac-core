# rbac-core

[![npm version][npm-badge]][npm-url]
[![Build Status][travis-badge]][travis-url]
[![Coverage Status][coveralls-badge]][coveralls-url]
[![Dependency Status][david-badge]][david-url]

> The RBAC core from hapi-rbac

> This is inspired by the [XACML](https://en.wikipedia.org/wiki/XACML) policies.

## Versions

* `1.0.0` [Release Notes](https://github.com/franciscogouveia/rbac-core/issues/12)
* `2.0.0` [Release Notes](https://github.com/franciscogouveia/rbac-core/issues/15)

## How to use it

First, install

```
npm install --save rbac-core
```

Import it to your project

```js
const Rbac = require('rbac-core');
const DataRetrievalRouter = Rbac.DataRetrievalRouter;
```

Create your data sources in the data retrieval router

```js
const dataRetrieverRouter = new DataRetrievalRouter();

/**
 * register(prefixes, dataretriever): registers a data retriever.
 *
 * prefixes - a string or array of strings with prefixes which this data retriever will be associated
 * dataretriever - a function with the following signature
 *         source - The requested prefix
 *         key - the key being requested
 *         context - An object with contextual information
 **/
dataRetrieverRouter.register('credentials', (source, key, context) => {

    // Obtain your value (e.g. from the context)
    const value = context[key];

    return value;
});

// You can handle multiple prefixes with a single data retriever
dataRetrieverRouter.register(['connection', 'status'], (source, key, context) => {

    let value;

    switch (source) {
        case 'connection':
            // Obtain connection info
            value = context.connection[key];
            break;
        case 'status':
            // Obtain from somewhere else
            value = getStatusValue(key);
            break;
    }

    return value;
});
```

Evaluate your policies against a certain context

```js
const context = {
    user: {
        username: 'francisco',
        group: ['admin', 'developer'],
        validated: true
    },
    connection: {
        remoteip: '192.168.0.123',
        remoteport: 90,
        localip: '192.168.0.2'
        localport: 80
    }
};

dataRetrieverRouter.setContext(context);

const policy = {
    target: [{ 'credentials:username': 'francisco' }, { 'credentials:group': 'admin' }], // if username is 'francisco' OR group is 'admin'
    apply: 'deny-overrides', // permit, unless one denies
    rules: [
        {
            target: { 'credentials:group': 'admin', 'credentials:validated': false }, // if group is 'admin' AND is not validated
            effect: 'deny'  // then deny (deny access to users that are not validated)
        },
        {
            target: { 'connection:remoteip': ['192.168.0.2', '192.168.0.3'] }, // if remoteip is one of '192.168.0.2' or '192.168.0.3'
            effect: 'deny'  // then deny (deny blacklisted ips)
        },
        {
            effect: 'permit' // else permit
        }
    ]
};

Rbac.evaluatePolicy(policy, dataRetrieverRouter, (err, result) => {

    switch (result) {
        case Rbac.PERMIT:
            console.log('ACCESS GRANTED');
            break;
        case Rbac.DENY:
            console.log('ACCESS DENIED');
            break;
    }
});

```

If you want to extend your existent data retriever router, you can do it.

```js
// You can just extend
const dataRetrieverRouter1 = dataRetrieverRouter.createChild();

// You can also directly add context to the extension, for isolation
const dataRetrieverRouter2 = dataRetrieverRouter.createChild(context);
```

Both `dataRetrieverRouter1` and `dataRetrieverRouter2` will have all the registered data retrievers from `dataRetrieverRouter`.

Changes to `dataRetrieverRouter` will influence `dataRetrieverRouter1` and `dataRetrieverRouter2`.

Changes to any of `dataRetrieverRouter1` or `dataRetrieverRouter2` will not cause influence on any data retriever routers, but themselves.

Contexts are preserved per data retriever router.

You can also get data from data retriever router

```js
dataRetrieverRouter.get('credentials:username', (err, result) => {
    ...
});
```

And you can override the context on get, by passing it in the second argument

```js
dataRetrieverRouter.get('credentials:username', { username: 'the_overrider', group: ['anonymous'] }, (err, result) => {
    ...
});
```

## Learn more about _Rule Based Access Control_

To have a better idea of how this works, you can check my Bachelor's project presentation about XACML
[here](http://helios.av.it.pt/attachments/download/559/_en_XACML.PAPOX.Presentation.pdf) (english),
or [here](http://helios.av.it.pt/attachments/download/557/_pt_XACML.PAPOX.Presentation.pdf) (portuguese).

Even though this plugin doesn't implement the XACML specification, it was based on its policies.

[npm-badge]: https://img.shields.io/npm/v/rbac-core.svg
[npm-url]: https://npmjs.com/package/rbac-core
[travis-badge]: https://travis-ci.org/franciscogouveia/rbac-core.svg?branch=master
[travis-url]: https://travis-ci.org/franciscogouveia/rbac-core
[coveralls-badge]:https://coveralls.io/repos/github/franciscogouveia/rbac-core/badge.svg?branch=master
[coveralls-url]: https://coveralls.io/github/franciscogouveia/rbac-core?branch=master
[david-badge]: https://david-dm.org/franciscogouveia/rbac-core.svg
[david-url]: https://david-dm.org/franciscogouveia/rbac-core
