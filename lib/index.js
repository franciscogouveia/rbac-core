'use strict';

const Async = require('async');
const Boom = require('boom');
const DataRetrievalRouter = require('./DataRetrievalRouter');

const DENY = 0;
const PERMIT = 1;
const UNDETERMINED = 3;

const internals = {};

/**
 * Evaluate a single Policy of PolicySet
 *
 **/
internals.evaluatePolicy = (item, dataRetriever, callback) => {

    if (!item) {
        return callback(Boom.badImplementation('RBAC configuration error: null item'));
    }

    if (!dataRetriever) {
        return callback(Boom.badImplementation('RBAC configuration error: null data retriever'));
    }

    if (!(dataRetriever instanceof DataRetrievalRouter)) {
        return callback(Boom.badImplementation('RBAC configuration error: invalid data retriever'));
    }

    if (!item.apply) {
        // Default combinatory algorithm
        item.apply = 'permit-overrides';
    }

    if (!(item.apply instanceof Function)) {
        if (!internals.combineAlg[item.apply]) {
            return callback(Boom.badImplementation('RBAC error: combinatory algorithm does not exist: ' + item.apply));
        }

        item.apply = internals.combineAlg[item.apply];
    }

    internals.evaluateTarget(item.target, dataRetriever, (err, applies) => {

        if (err) {
            return callback(err);
        }

        if (!applies) {
            return callback(null, UNDETERMINED);
        }

        // Policy set
        if (item.policies) {

            return item.apply(item.policies, dataRetriever, internals.evaluatePolicy, callback);
        }

        // Policy
        if (item.rules) {

            return item.apply(item.rules, dataRetriever, internals.evaluateRule, callback);
        }

        // Rule
        internals.evaluateRule(item, dataRetriever, callback);
    });
};

const VALID_EFFECTS = ['permit', 'deny'];
/**
 * Evaluate a single rule.
 *
 * {
 *    'target': [...],
 *    'effect': PERMIT, DENY
 * }
 **/
internals.evaluateRule = (rule, dataRetriever, callback) => {

    if (!rule) {
        return callback(Boom.badImplementation('RBAC rule is missing'));
    }

    if (!rule.effect) {
        return callback(Boom.badImplementation('RBAC rule effect is missing'));
    }

    if (VALID_EFFECTS.indexOf(rule.effect) === -1) {
        return callback(Boom.badImplementation('RBAC rule effect is invalid. Use one of', VALID_EFFECTS));
    }

    internals.evaluateTarget(rule.target, dataRetriever, (err, applies) => {

        if (err) {
            return callback(err);
        }

        if (!applies) {
            return callback(null, UNDETERMINED);
        }

        switch (rule.effect) {
            case 'permit':
            case PERMIT:
                return callback(null, PERMIT);
            case 'deny':
            case DENY:
                return callback(null, DENY);
            default:
                return callback(Boom.badImplementation('RBAC rule error: invalid effect ' + rule.effect));
        }
    });
};

/**
 * Evaluate a target
 * The objects in the target array are matched with OR condition. The keys in an object are matched with AND condition.
 *
 * [
 *   {
 *     'credentials:username': 'francisco', // AND
 *     'credentials:group': 'admin'
 *   }, // OR
 *   {
 *     'credentials:username': 'francisco', // AND
 *     'credentials:group': 'writer'
 *   }
 * ]
 *
 * This target applies to francisco, if he is in the group admin or writer.
 *
 **/
internals.evaluateTarget = (target, dataRetriever, callback) => {

    if (!target) {
        // Applies by default, when no target is defined
        return callback(null, true);
    }

    if (target instanceof Array) {
        if (!target.length) {
            return callback(Boom.badImplementation('RBAC target error: invalid format. The array in target should have at least one element.'));
        }
    }
    else {
        // Allow defining a single element in target without using an array
        target = [target];
    }

    const tasks = [];

    for (const index in target) {

        const element = target[index];

        tasks.push(internals.evaluateTargetElement(dataRetriever, element));
    }

    Async.parallel(tasks, (err, result) => {

        if (err) {
            return callback(err);
        }

        // At least one should apply (OR)
        const applicables = result.filter((value) => value);

        callback(null, applicables.length > 0);
    });
};

internals.evaluateTargetElement = (dataRetriever, element) => {

    return (callback) => {

        const promises = Object.keys(element).map((key) => internals.evaluateTargetElementKey(dataRetriever, element, key));

        Promise.all(promises)
        .then((results) => {

            // Should all apply (AND)
            const nonApplicable = results.filter((value) => !value);

            callback(null, nonApplicable.length === 0);
        })
        .catch((err) => callback(err))
    };
};

/**
 * If target is defined as:
 * { field: "credentials:user" }
 * then this definition should be replaced by
 * a value from dataRetriever for matching.
 *
 * @param dataRetriever
 * @param definedValue
 * @returns Promise
 **/
internals.getTargetValue = (dataRetriever, definedValue) => {

    if(typeof definedValue === "object") {
        if (definedValue.field) {
            return dataRetriever.get(definedValue.field);
        }
    }

    return Promise.resolve(definedValue);
};

internals.evaluateTargetElementKey = (dataRetriever, element, key) => {

    return Promise.all([
        internals.getTargetValue(dataRetriever, element[key]),
        dataRetriever.get(key)
    ])
    .then((results) => {

        const targetValue = results[0];
        const value = results[1];
        return internals._targetApplies(targetValue, value);
    });
};

/**
 * If target has more than one value, all of them should match
 **/
internals._targetApplies = (targets, values) => {

    if (!Array.isArray(targets)) {
        targets = [targets];
    }

    if (!Array.isArray(values)) {
        values = [values];
    }

    // Should match all
    // So: continue looping unless one doesn't
    for (const index in targets) {
        const target = targets[index];
        const matches = values.filter((value) => {

            if (target instanceof RegExp) {
                return target.test(value);
            }

            return value === target;
        });

        if (matches.length === 0) {
            return false;
        }
    }

    // All targets are matched
    return true;
};

/**
 * Combinator algorithms:
 *
 *   - permit-overrides - If at least one permit is evaluated, then permit
 *   - deny-overrides - If at least one deny is evaluated, then deny
 *   - only-one-applicable -
 *   - first-applicable - Only evaluate the first applicable rule
 **/
internals.combineAlg = {};

internals.combineAlg['permit-overrides'] = (items, information, fn, callback) => {

    if (!items || items.length === 0) {
        return callback(null, UNDETERMINED);
    }

    const tasks = [];

    for (let i = 0; i < items.length; ++i) {
        tasks.push(fn.bind(null, items[i], information));
    }

    Async.parallel(tasks, (err, results) => {

        if (err) {
            return callback(err);
        }

        for (let i = 0; i < results.length; ++i) {
            if (results[i] === PERMIT) {
                return callback(null, PERMIT);
            }
        }

        callback(null, DENY);
    });
};

internals.combineAlg['deny-overrides'] = (items, information, fn, callback) => {

    if (!items || items.length === 0) {
        return callback(null, UNDETERMINED);
    }

    const tasks = [];

    for (let i = 0; i < items.length; ++i) {
        tasks.push(fn.bind(null, items[i], information));
    }

    Async.parallel(tasks, (err, results) => {

        if (err) {
            return callback(err);
        }

        for (let i = 0; i < results.length; ++i) {
            if (results[i] === DENY) {
                return callback(null, DENY);
            }
        }

        callback(null, PERMIT);
    });
};

exports = module.exports = {
    evaluatePolicy: internals.evaluatePolicy,
    evaluateRule: internals.evaluateRule,
    evaluateTarget: internals.evaluateTarget,
    DENY: DENY,
    PERMIT: PERMIT,
    UNDETERMINED: UNDETERMINED,
    DataRetrievalRouter: DataRetrievalRouter
};
